#!/usr/bin/env bash
set -euo pipefail

# 从 source 文件中筛出不在 baseline 文件里的行，并按固定大小切分输出。
SOURCE_FILE="${1:-datasets/tags/408/001_408}"
BASELINE_FILE="${2:-datasets/tags/408/baseline.txt}"
OUTPUT_DIR="${3:-datasets/tags/408/non_baseline_chunks}"
CHUNK_SIZE="${4:-100}"

if [[ ! -f "$SOURCE_FILE" ]]; then
  echo "错误: source 文件不存在: $SOURCE_FILE" >&2
  exit 1
fi

if [[ ! -f "$BASELINE_FILE" ]]; then
  echo "错误: baseline 文件不存在: $BASELINE_FILE" >&2
  exit 1
fi

if ! [[ "$CHUNK_SIZE" =~ ^[1-9][0-9]*$ ]]; then
  echo "错误: CHUNK_SIZE 必须是正整数，当前值: $CHUNK_SIZE" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR"/chunk_*.txt

awk -v chunk_size="$CHUNK_SIZE" -v outdir="$OUTPUT_DIR" '
  NR == FNR {
    baseline[$0] = 1
    next
  }
  !($0 in baseline) && $0 != "" {
    idx = int(count / chunk_size) + 1
    file = sprintf("%s/chunk_%03d.txt", outdir, idx)
    print $0 >> file
    count++
  }
  END {
    print "筛选后总条数: " count
    print "输出目录: " outdir
    if (count == 0) {
      print "未发现差异条目。"
    } else {
      chunk_count = int((count - 1) / chunk_size) + 1
      print "分片文件数: " chunk_count
    }
  }
' "$BASELINE_FILE" "$SOURCE_FILE"
