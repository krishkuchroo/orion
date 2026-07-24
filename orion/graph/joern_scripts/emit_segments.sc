// orion/graph/joern_scripts/emit_segments.sc
// Flatgraph per-function segment producer (Joern 4.0.569 / flatgraph-core 0.1.32 / codepropertygraph
// 1.7.70). Streams one segment per cpg.method to `segments.jsonl` in the frozen spec-§5 schema.
//
// ── Accessor spellings, PINNED by a live reflection probe against fixtures/NodeGoat/cpg.bin ──
//   Node classes:        io.shiftleft.codepropertygraph.generated.nodes.{Method,Call,Identifier,File,...}
//   node id:             `n.id` -> scala Long, SAME integer space as the GraphSON `g:Int64` ids the
//                        Python partition keys on (e.g. method :program -> 107374182401 both places).
//   full property dump:  `n.propertiesMap` -> java.util.Map[String,Object] with UPPERCASE schema keys
//                        (NAME, FULL_NAME, ARGUMENT_INDEX, INDEX, METHOD_FULL_NAME, ...) and PLAIN
//                        scalar/Seq values (NO GraphSON type-tagging). Verified: every ARGUMENT-edge
//                        child carries ARGUMENT_INDEX and every METHOD_PARAMETER_IN carries INDEX in
//                        propertiesMap (no default-omission for the props summaries read).
//   AST subtree edges:   `n._astOut`         (child nodes; total 9336 == GraphSON AST)
//   REACHING_DEF edges:  `n._reachingDefOut` (targets;      total 14414 == GraphSON REACHING_DEF)
//   ARGUMENT edges:      `n._argumentOut`    (arg children)
//   CONTAINS edges:      `n._containsOut`
//   CALL -> callee id:   `call._callOut`     (resolved callee METHOD node; may be an external stub)
//   SOURCE_FILE -> FILE: `method._sourceFileOut`  (the real accessor is `_sourceFileOut`, NOT the
//                        design-doc's guessed `_fileViaSourceFileOut`)
//
// ── Why CpgLoader.load, not importCpg ──
//   `importCpg` re-applies default post-processing overlays on load, which SYNTHESIZES 5 extra JS
//   type-recovery method stubs (`_tmp_1:db:<returnValue>:...:find:<returnValue>:toArray`) -> 286
//   methods, diverging from the 281 that `joern-export` (the Python reference's graph) sees.
//   `CpgLoader.load` opens the STORED graph as-is: 281 methods / 9336 AST / 14414 REACHING_DEF,
//   byte-for-byte the export's node/edge set. That exact match is what makes partition-equivalence
//   and closure-parity provable.
//
// ── Ownership == taint_summary.owner_map, BY CONSTRUCTION ──
//   We do NOT use `m.ast` (Joern's downward AST descent). Instead we build the global AST-parent
//   relation from every `_astOut` edge (child -> parent) and climb each node to its NEAREST
//   enclosing METHOD (a METHOD owns itself; a node under no METHOD is owner-less). This is the SAME
//   climb as owner_map, so ownership matches for nested lambdas/closures too: climbing from a node
//   inside a nested lambda stops at the lambda METHOD, never leaking into the outer method.
import io.shiftleft.codepropertygraph.cpgloading.CpgLoader
import io.shiftleft.codepropertygraph.generated.nodes.Expression
import java.io.PrintWriter
import scala.collection.mutable
import scala.jdk.CollectionConverters._

@main def main(cpgPath: String, outPath: String): Int = {
  val cpg = CpgLoader.load(cpgPath)   // stored graph, no overlay re-application (see header)

  // ── JSON helpers (emit plain scalars; the consumer feeds these straight to _unwrap/_prop) ──
  def jsonStr(s: String): String = {
    val sb = new StringBuilder("\"")
    var i = 0
    while (i < s.length) {
      s.charAt(i) match {
        case '"'  => sb.append("\\\"")
        case '\\' => sb.append("\\\\")
        case '\n' => sb.append("\\n")
        case '\r' => sb.append("\\r")
        case '\t' => sb.append("\\t")
        case c if c < 0x20 => sb.append("\\u%04x".format(c.toInt))
        case c    => sb.append(c)
      }
      i += 1
    }
    sb.append('"').toString
  }
  def jsonVal(v: Any): String = v match {
    case null                            => "null"
    case s: String                       => jsonStr(s)
    case b: java.lang.Boolean            => b.toString
    case n: java.lang.Number             => n.toString
    case it: scala.collection.Iterable[_] => "[" + it.map(jsonVal).mkString(",") + "]"
    case jc: java.util.Collection[_]     => "[" + jc.asScala.map(jsonVal).mkString(",") + "]"
    case other                           => jsonStr(other.toString)
  }
  // `extra` are already-serialized (KEY, jsonValue) pairs to add ONLY when propertiesMap lacks the
  // key. flatgraph's propertiesMap omits a property sitting at its schema default; joern-export's
  // GraphSON keeps it. ARGUMENT_INDEX (default -1) is the one such property the summaries read, so we
  // re-add it from the typed Expression.argumentIndex accessor to stay byte-faithful to the oracle.
  def serializeProps(pm: java.util.Map[_, _], extra: List[(String, String)]): String = {
    val base = pm.asScala.map { case (k, v) => jsonStr(k.toString) + ":" + jsonVal(v) }.toList
    val add  = extra.filterNot { case (k, _) => pm.containsKey(k) }.map { case (k, vs) => jsonStr(k) + ":" + vs }
    "{" + (base ++ add).mkString(",") + "}"
  }
  def vertexJson(id: Long, label: String, body: String): String =
    s"""{"id":$id,"label":${jsonStr(label)},"properties":$body}"""

  val allNodes = cpg.all.l

  // ── global ownership: nodeId -> nearest enclosing METHOD id (== owner_map) ──
  val NONE = -1L
  val isMethod = mutable.HashSet.empty[Long]
  allNodes.foreach { n => if (n.label == "METHOD") isMethod.add(n.id) }
  val astParent = mutable.LongMap.empty[Long]        // child id -> parent id (from every AST edge)
  allNodes.foreach { n => n._astOut.foreach { c => astParent.update(c.id, n.id) } }
  val ownerCache = mutable.LongMap.empty[Long]
  def owner(id0: Long): Long = ownerCache.getOrElse(id0, {
    var cur = id0; var guard = 0; var result = NONE; var done = false
    while (!done && guard < 512) {
      guard += 1
      if (isMethod.contains(cur)) { result = cur; done = true }
      else astParent.get(cur) match {
        case Some(p) => cur = p
        case None    => done = true      // no AST parent and not a METHOD -> owner-less
      }
    }
    ownerCache.update(id0, result); result
  })

  // ── bucket vertices (as JSON) by owning method (INCLUDING the METHOD vertex itself) ──
  def vExtra(n: Any): List[(String, String)] = n match {
    case e: Expression => List(("ARGUMENT_INDEX", e.argumentIndex.toString))   // -1 default kept
    case _             => Nil
  }
  val vertsByMethod = mutable.LongMap.empty[mutable.ArrayBuffer[String]]
  allNodes.foreach { n =>
    val o = owner(n.id)
    if (o != NONE) vertsByMethod.getOrElseUpdate(o, mutable.ArrayBuffer.empty) +=
      vertexJson(n.id, n.label, serializeProps(n.propertiesMap, vExtra(n)))
  }

  // ── bucket wholly-inside edges (AST / REACHING_DEF / ARGUMENT / CONTAINS) by owner ──
  // and, in the SAME pass over REACHING_DEF, compute the cross-method closure seam (== _closure_edges
  // filtered to the part the stitch consults):
  //   for a cross RD edge o->i (owner(o) != owner(i)) with owner(i) defined:
  //     closure_targets(owner(i)) += i          (TARGET side: keep method-less sources)
  //     if owner(o) defined: cross_rd(owner(o)) += (o,i)   (SOURCE side: drop method-less targets)
  //   an edge whose target is owner-less (owner(i)==NONE) contributes nothing (matches _closure_edges).
  val edgesByMethod   = mutable.LongMap.empty[mutable.ArrayBuffer[String]]
  val crossByMethod   = mutable.LongMap.empty[mutable.ArrayBuffer[String]]
  val targetsByMethod = mutable.LongMap.empty[mutable.LinkedHashSet[Long]]
  def addEdge(m: Long, s: String) = edgesByMethod.getOrElseUpdate(m, mutable.ArrayBuffer.empty) += s
  def edgeJson(label: String, o: Long, oLbl: String, i: Long, iLbl: String): String =
    s"""{"label":${jsonStr(label)},"outV":$o,"inV":$i,"outVLabel":${jsonStr(oLbl)},"inVLabel":${jsonStr(iLbl)}}"""

  allNodes.foreach { n =>
    val nid = n.id; val nlbl = n.label; val mo = owner(nid)
    n._astOut.foreach { c =>
      val mi = owner(c.id)
      if (mo != NONE && mo == mi) addEdge(mo, edgeJson("AST", nid, nlbl, c.id, c.label))
    }
    n._argumentOut.foreach { c =>
      val mi = owner(c.id)
      if (mo != NONE && mo == mi) addEdge(mo, edgeJson("ARGUMENT", nid, nlbl, c.id, c.label))
    }
    n._containsOut.foreach { c =>
      val mi = owner(c.id)
      if (mo != NONE && mo == mi) addEdge(mo, edgeJson("CONTAINS", nid, nlbl, c.id, c.label))
    }
    n._reachingDefOut.foreach { c =>
      val cid = c.id; val mi = owner(cid)
      if (mo != NONE && mo == mi) {
        addEdge(mo, edgeJson("REACHING_DEF", nid, nlbl, cid, c.label))    // intra: inside the slice
      } else if (mi != NONE) {                                            // cross-method rd (closure)
        targetsByMethod.getOrElseUpdate(mi, mutable.LinkedHashSet.empty).add(cid)
        if (mo != NONE)
          crossByMethod.getOrElseUpdate(mo, mutable.ArrayBuffer.empty) += s"[$nid,$cid]"
      }
    }
  }

  // ── callsites: one per REAL call (methodFullName not <operator>.*); callee_id direct from _callOut ──
  val callsitesByMethod = mutable.LongMap.empty[mutable.ArrayBuffer[String]]
  cpg.call.foreach { c =>
    val mfn = c.methodFullName
    if (mfn == null || !mfn.startsWith("<operator>")) {
      val mo = owner(c.id)
      if (mo != NONE) {
        val calleeId = c._callOut.nextOption().map(_.id.toString).getOrElse("null")
        val args = c._argumentOut.map { a =>
          // flatgraph's propertiesMap OMITS a property at its schema default; joern-export's GraphSON
          // includes it. ARGUMENT_INDEX's default is -1, so fall back to -1 to match _prop's view.
          val aiObj = a.propertiesMap.get("ARGUMENT_INDEX")
          val ai = if (aiObj == null) "-1" else aiObj.toString
          jsonStr(ai) + ":" + a.id
        }.toList
        val cs = s"""{"call_id":${c.id},"callee_id":$calleeId,""" +
                 s""""callee_full_name":${jsonStr(if (mfn == null) "" else mfn)},""" +
                 s""""args":{${args.mkString(",")}}}"""
        callsitesByMethod.getOrElseUpdate(mo, mutable.ArrayBuffer.empty) += cs
      }
    }
  }

  // ── call_edges: EVERY CALL -> METHOD out-edge (RESOLVES_TO source), one pair per edge, bucketed
  // by the CALL node's owner. UNLIKE `callsites` (which is taint-shaped: real calls only, a single
  // callee_id), this is UNFILTERED: it includes <operator>.* calls AND every callee of a multi-callee
  // (over-approximated) call site. Legacy `project_graphson` persists a RESOLVES_TO for EVERY
  // CALL -> METHOD edge, so the consumer reconstructs RESOLVES_TO from THIS field, never from the
  // taint `callsites` (a strict subset). Same typed `_callOut` accessor as callsites, but no
  // real-call restriction and ALL callees, not just the first. The taint `callsites` field above is
  // left EXACTLY as is (the taint path depends on it staying byte-identical).
  val callEdgesByMethod = mutable.LongMap.empty[mutable.ArrayBuffer[String]]
  cpg.call.foreach { c =>
    val mo = owner(c.id)
    if (mo != NONE) {
      c._callOut.foreach { callee =>
        callEdgesByMethod.getOrElseUpdate(mo, mutable.ArrayBuffer.empty) += s"[${c.id},${callee.id}]"
      }
    }
  }

  // ── emit ──
  val pw = new PrintWriter(outPath)
  try {
    // preamble: FILE nodes (full property dump incl. NAME), seg = -1
    val files = cpg.file.l.map(f => vertexJson(f.id, f.label, serializeProps(f.propertiesMap, Nil)))
    pw.println(s"""{"seg":-1,"files":[${files.mkString(",")}]}""")

    var seg = 0
    cpg.method.foreach { m =>
      val mid       = m.id
      val vjson     = vertsByMethod.getOrElse(mid, mutable.ArrayBuffer.empty).mkString(",")
      val ejson     = edgesByMethod.getOrElse(mid, mutable.ArrayBuffer.empty).mkString(",")
      val fileId    = m._sourceFileOut.nextOption().map(_.id.toString).getOrElse("null")
      val csjson    = callsitesByMethod.getOrElse(mid, mutable.ArrayBuffer.empty).mkString(",")
      val cejson    = callEdgesByMethod.getOrElse(mid, mutable.ArrayBuffer.empty).mkString(",")
      val crossJson = crossByMethod.getOrElse(mid, mutable.ArrayBuffer.empty).mkString(",")
      val tgtJson   = targetsByMethod.getOrElse(mid, mutable.LinkedHashSet.empty).mkString(",")
      pw.println(
        s"""{"seg":$seg,"method_id":$mid,"vertices":[$vjson],"edges":[$ejson],""" +
        s""""source_file":{"file_id":$fileId},"callsites":[$csjson],"call_edges":[$cejson],""" +
        s""""cross_rd":[$crossJson],"closure_targets":[$tgtJson]}""")
      seg += 1
    }
    println(s"emit_segments wrote $seg per-function segments to $outPath")
    seg
  } finally pw.close()
}
