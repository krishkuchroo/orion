#!/bin/bash
# Orion-LM run C1, training (Krish starts it): opens TensorBoard (live loss / learning rate / tokens per second /
# peak memory / gradient norm) in the browser, then trains in this terminal under the 7 GB guard with the Mac kept
# awake. 1 epoch over train/data/mlx/train.jsonl (balanced data v2), LoRA r16/alpha16 on the top 8 layers of
# models/orion-lm-base, validation loss on 100 fixed dev rows every 100 steps, a checkpoint every
# 25 steps. Ctrl-C stops it (the guard kills the whole process group).
#
#   bash train/start_c1.sh                                              # start
#   bash train/start_c1.sh --resume train/runs/qwen35-c1/checkpoint-50  # continue a stopped run
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=train/runs/qwen35-c1
UNSLOTH_BIN=~/.unsloth/studio/unsloth_studio/bin
[ -s train/data/mlx/train.jsonl ] || { echo "no train/data/mlx/train.jsonl yet: build it with examples.export(sampler='balanced') + train.unsloth_data --tokenized"; exit 1; }
mkdir -p "$OUT/runs"

if ! curl -s -o /dev/null http://localhost:6006; then
  nohup "$UNSLOTH_BIN/tensorboard" --logdir "$OUT/runs" --port 6006 --reload_interval 15 > "$OUT/tensorboard.log" 2>&1 &
  for _ in $(seq 30); do curl -s -o /dev/null http://localhost:6006 && break; sleep 1; done
fi
open http://localhost:6006
echo "Live graphs: http://localhost:6006 (TensorBoard; graphs appear after the first step, about 2 min in)"

exec caffeinate -i ./.venv/bin/python -m train.guard --log "$OUT/train.log" --max-proc-mem-mb 7168 --max-swap-growth-mb 6144 -- \
  "$UNSLOTH_BIN/python" -m train.mlx_train --model models/orion-lm-base --data train/data/mlx/train.jsonl --out "$OUT" \
  --epochs 1 --grad-accum 16 --save-steps 25 --last-n-layers 8 --lora-r 16 --lora-alpha 16 \
  --eval-data train/data/mlx/dev.jsonl --eval-rows 100 --eval-steps 100 "$@"
