#!/usr/bin/env bash
# ============================================================================
# cq-unicom-speedtest.sh — 重庆联通(cesu.cqwin.com)宽带测速脚本(下行)
#
# 协议来源:分析 cesu.cqwin.com.har(Chrome 抓包)与 broadband_h5.js 逆向:
#   1. POST /h5-web/servlet/pushIpCheckIndex  获取宽带信息与探针会话(签约带宽 dbCode)
#   2. POST /h5-web/servlet/pushCheckSurroUpload  环境预检(必需,缺预检报 1010)
#   3. POST /h5-web/servlet/testAllAdrUpload  动态获取测速服务器列表
#   4. GET  <server>/sts-base-node//?ran=<随机>  对每个服务器测延迟
#   5. GET  <server>/sts-base-node/servlet/wxspeed?ran=<随机>
#        下载 1GiB (Content-Length: 1073741824) 随机数据流测速
#
# 下行接口无需任何认证,curl 即可直接测速。
# 界面风格参考 ui-ux-pro-max 设计系统:Dark OLED + 语义化颜色。
#
# 依赖:bash + curl + awk + sed + grep(Windows 下用 Git Bash / WSL)
#
# 用法示例:
#   ./cq-unicom-speedtest.sh                       # 默认:12 秒 × 3 轮 × 4 连接
#   ./cq-unicom-speedtest.sh -t 15 -n 5            # 每次 15 秒,共 5 轮
#   ./cq-unicom-speedtest.sh -c 8                  # 8 连接并发
#   ./cq-unicom-speedtest.sh -b 1000               # 手动指定签约带宽(兆),用于对比
#   ./cq-unicom-speedtest.sh -s 123.147.219.182    # 手动指定测速服务器
#   ./cq-unicom-speedtest.sh -p                    # 只测各服务器延迟
# ============================================================================

set -uo pipefail

# 中断(Ctrl+C)时清理测速临时文件
trap 'rm -f /tmp/cqst.*' EXIT

# ---------- 配置 ----------
API_BASE="http://cesu.cqwin.com"
# 从 HAR 抓包提取的测速服务器(服务器Url 前缀,包含 /sts-base-node/)
BUILTIN_SERVERS=(
  "http://123.147.219.190:8090/sts-base-node/"
  "http://123.147.219.186:8090/sts-base-node/"
  "http://123.147.219.182:8090/sts-base-node/"
  "http://123.147.219.178:8090/sts-base-node/"
  "http://123.147.220.126:8090/sts-base-node/"
  "http://123.147.220.122:8090/sts-base-node/"
  "http://221.13.126.6:8090/sts-base-node/"
  "http://221.13.126.2:8090/sts-base-node/"
)

# ---------- 默认参数 ----------
DURATION=12        # 每次测速时长(秒),官方单次 maxDataTime=15s
ROUNDS=3           # 测速轮数
CONCURRENCY=4      # 下行并发连接数,官方 thredNum=10
SERVER=""          # 手动指定服务器 IP
BANDWIDTH=""       # 手动指定签约带宽(Mbps),空则自动获取
PING_ONLY=0

# ---------- ANSI 颜色(自动检测终端能力:真彩色 > 256色 > 16色) ----------
# 语义色(ui-ux-pro-max Dark OLED):Accent #22C55E / Destructive #EF4444
# / Border #334155 / 警示 #F59E0B / Foreground #F8FAFC
# 部分终端(SSH 客户端)对 16 色亮色(91-97)渲染异常(全部显示为白/灰),
# 因此优先使用真彩色/256 色精确色值,16 色回退用基础色(31-37)。
if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
  if [[ "${COLORTERM:-}" =~ (truecolor|24bit) ]]; then
    # 真彩色(24bit):精确语义色
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_GRAY=$'\033[38;2;100;116;139m'    # slate-500
    C_RED=$'\033[38;2;239;68;68m'       # red-500
    C_GREEN=$'\033[38;2;34;197;94m'     # green-500
    C_YELLOW=$'\033[38;2;245;158;11m'   # amber-500
    C_BLUE=$'\033[38;2;59;130;246m'     # blue-500
    C_CYAN=$'\033[38;2;34;211;238m'     # cyan-400
    C_WHITE=$'\033[38;2;248;250;252m'   # slate-50
  elif [[ "${TERM:-}" =~ 256color ]]; then
    # 256 色:接近语义色的索引
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_GRAY=$'\033[38;5;244m'            # 灰
    C_RED=$'\033[38;5;203m'             # 红
    C_GREEN=$'\033[38;5;113m'           # 绿
    C_YELLOW=$'\033[38;5;214m'          # 琥珀
    C_BLUE=$'\033[38;5;75m'             # 蓝
    C_CYAN=$'\033[38;5;81m'             # 青
    C_WHITE=$'\033[38;5;231m'           # 白
  else
    # 16 色基础色(兼容性最佳)
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_GRAY=$'\033[90m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'; C_WHITE=$'\033[37m'
  fi
else
  C_RESET=''; C_BOLD=''; C_DIM=''; C_GRAY=''; C_RED=''; C_GREEN=''
  C_YELLOW=''; C_BLUE=''; C_CYAN=''; C_WHITE=''
fi

# ---------- 输出工具 ----------
c() { printf '%s%s%s' "${2:-$C_RESET}" "$1" "$C_RESET"; }  # c "文本" "颜色"(不换行)
cli() { printf '%s%s%s\n' "${2:-$C_RESET}" "$1" "$C_RESET"; }  # cli "文本" "颜色"(换行)
red()   { cli "$*" "$C_RED"; }
green() { cli "$*" "$C_GREEN"; }
yellow(){ cli "$*" "$C_YELLOW"; }
cyan()  { cli "$*" "$C_CYAN"; }
gray()  { cli "$*" "$C_GRAY"; }
dim()   { cli "$*" "$C_DIM"; }

usage() {
  cat <<'EOF'
用法: cq-unicom-speedtest.sh [选项]

  -t <秒>   每次下载测速时长,默认 12(官方单次 15 秒)
  -n <轮数> 测速轮数,默认 3,取最大值作为结果
  -c <并发> 并发连接数,默认 4(官方为 10 并发)
  -b <兆>   手动指定签约带宽(Mbps),用于与实测结果对比;默认自动从接口获取
  -s <IP>   手动指定测速服务器(如 123.147.219.182),跳过延迟选择
  -p        只测各服务器延迟,不进行下载测速
  -h        显示本帮助

示例:
  ./cq-unicom-speedtest.sh               # 基本测速
  ./cq-unicom-speedtest.sh -t 15 -c 8    # 15 秒 × 8 并发
EOF
}

# ---------- 服务器列表:动态获取(官方链路),失败回退内置列表 ----------
# 官方流程:pushIpCheckIndex 获取真实探针会话 → pushCheckSurroUpload 环境预检
# → testAllAdrUpload 返回节点列表(缺预检会报 1010"请先进行环境预检")
get_server_list() {
  local servers=() now resp
  now=$(date '+%Y-%m-%d %H:%M:%S')
  # 1. 获取真实探针会话(pushIpCheckIndex)
  resp=$(curl -s --max-time 8 -X POST "$API_BASE/h5-web/servlet/pushIpCheckIndex" \
    -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
    -H 'X-Requested-With: XMLHttpRequest' \
    --data-urlencode "jsonParam={\"type\":\"5\",\"collectType\":\"3\",\"terminalIp\":\"\",\"currentTime\":\"$now\"}" 2>/dev/null)
  local p s a t
  p=$(printf '%s' "$resp" | grep -oE '"probeId":"[^"]*"' | sed 's/.*":"//; s/"//')
  s=$(printf '%s' "$resp" | grep -oE '"session":"[^"]*"' | sed 's/.*":"//; s/"//')
  a=$(printf '%s' "$resp" | grep -oE '"account":"[^"]*"' | sed 's/.*":"//; s/"//')
  t=$(printf '%s' "$resp" | grep -oE '"terminalIp":"[^"]*"' | sed 's/.*":"//; s/"//')
  if [[ -n "$p" ]]; then
    # 2. 环境预检(必需,否则 testAllAdrUpload 报 1010)
    curl -s --max-time 8 -X POST "$API_BASE/h5-web/servlet/pushCheckSurroUpload?d=0.$RANDOM" \
      -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
      -H 'X-Requested-With: XMLHttpRequest' \
      --data-urlencode "jsonParam={\"probeId\":\"$p\",\"type\":\"5\",\"collectType\":\"3\",\"session\":\"$s\",\"account\":\"$a\",\"terminalIp\":\"$t\",\"currentTime\":\"$now\",\"cmdId\":8,\"detectResult\":0,\"speedType\":\"H5_WEB\"}" >/dev/null 2>&1
    # 3. 获取测速节点列表
    resp=$(curl -s --max-time 8 -X POST "$API_BASE/h5-web/servlet/testAllAdrUpload?d=0.$RANDOM" \
      -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
      -H 'X-Requested-With: XMLHttpRequest' \
      --data-urlencode "jsonParam={\"probeId\":\"$p\",\"type\":\"5\",\"collectType\":\"3\",\"session\":\"$s\",\"account\":\"$a\",\"terminalIp\":\"$t\",\"currentTime\":\"$now\",\"speedType\":\"H5_WEB\"}" 2>/dev/null)
    while read -r line; do
      url=$(printf '%s' "$line" | sed 's/.*"serverUrl":"//; s/".*//')
      [[ -n "$url" ]] && servers+=("$url")
    done < <(printf '%s' "$resp" | grep -oE '"serverUrl":"[^"]*"')
    if [[ ${#servers[@]} -ge 1 ]]; then
      green "  已从官方接口动态获取 ${#servers[@]} 个测速节点" >&2
      printf '%s\n' "${servers[@]}"
      return 0
    fi
  fi
  yellow "  官方节点获取失败,回退内置列表" >&2
  printf '%s\n' "${BUILTIN_SERVERS[@]}"
}

# ---------- 宽带信息:pushIpCheckIndex → dbCode(签约带宽)/confCode(提速)/regionName/account ----------
fetch_broadband_info() {
  local now param resp
  now=$(date '+%Y-%m-%d %H:%M:%S')
  param="{\"type\":\"5\",\"collectType\":\"3\",\"terminalIp\":\"\",\"currentTime\":\"$now\"}"
  resp=$(curl -s --max-time 8 -X POST "$API_BASE/h5-web/servlet/pushIpCheckIndex" \
    -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
    -H 'Origin: http://cesu.cqwin.com' \
    -H 'X-Requested-With: XMLHttpRequest' \
    --data-urlencode "jsonParam=$param" 2>/dev/null)
  # 提取字段(全部走 stdout,供调用方赋值)
  local db conf region acct
  db=$(printf '%s' "$resp" | grep -oE '"dbCode":"[^"]*"' | sed 's/.*":"//; s/"//')
  conf=$(printf '%s' "$resp" | grep -oE '"confCode":"[^"]*"' | sed 's/.*":"//; s/"//')
  region=$(printf '%s' "$resp" | grep -oE '"regionName":"[^"]*"' | sed 's/.*":"//; s/"//')
  acct=$(printf '%s' "$resp" | grep -oE '"account":"[^"]*"' | sed 's/.*":"//; s/"//')
  printf '%s\t%s\t%s\t%s' "$db" "$conf" "$region" "$acct"
}

# 对单个服务器测延迟(3 次取最小,ms)
ping_server() {
  local base="$1" best=-1 t
  local rn=$RANDOM
  for _ in 1 2 3; do
    t=$(curl -s -o /dev/null --connect-timeout 3 --max-time 6 \
          -w '%{time_total}' "$base//?ran=$rn.$RANDOM" 2>/dev/null)
    t=$(awk -v x="$t" 'BEGIN{printf "%.3f", x}')
    if [[ -n "$t" ]] && awk -v t="$t" -v b="$best" 'BEGIN{exit !(b<0 || t<b)}'; then
      best=$t
    fi
  done
  if [[ "$best" =~ ^[0-9.]+$ ]]; then
    awk -v b="$best" 'BEGIN{printf "%.1f", b*1000}'
  else
    echo "-1"
  fi
}

# 解析服务器 URL 为 IP(用于显示)
server_ip() { printf '%s' "$1" | sed -E 's#https?://([^:/]+).*#\1#'; }

# ---------- 进度条渲染(输出到 stderr,不污染返回值) ----------
# 限时测速:进度按时间推进(已测秒/总时长),字节量显示在右侧
# 参数: $1 标签(如 "1/3") $2 已用秒数 $3 总时长(秒) $4 已传字节 $5 瞬时Mbps $6 平均Mbps
render_progress() {
  local label="$1" cur="$2" total="$3" bytes="$4" inst="$5" avg="$6"
  local pct bars j mb
  pct=$(awk -v b="$cur" -v t="$total" 'BEGIN{if(t>0) printf "%d", b*100/t; else print 0}')
  [[ $pct -gt 100 ]] && pct=100
  bars=$((pct * 25 / 100))
  mb=$(awk -v b="$bytes" 'BEGIN{printf "%.1f", b/1048576}')
  printf '\r  %s轮 %s:%s' "$C_DIM" "$label" "$C_RESET" >&2
  # 进度条:已下载段绿色(92)→未下载段灰色(90)
  printf '%s' "$C_GREEN" >&2
  for ((j=0; j<bars; j++)); do printf '█' >&2; done
  printf '%s' "$C_GRAY" >&2
  for ((j=bars; j<25; j++)); do printf '░' >&2; done
  printf '%s %3d%% | %s瞬时 %6s%s Mbps | %s平均 %6s%s Mbps | %s%6.1f%s MB\033[K' \
    "$C_RESET" "$pct" "$C_CYAN" "$inst" "$C_RESET" "$C_GREEN" "$avg" "$C_RESET" "$C_WHITE" "$mb" "$C_RESET" >&2
}

# ---------- 一次下载测速(支持并发) ----------
# 参数: $1 服务器URL $2 测速时长(秒) $3 并发连接数 $4 显示标签(如 "1/3")
# 返回: "字节数 耗时秒"
download_once() {
  local base="$1" duration="$2" concurrency="$3" label="$4"
  local tmp_prefix
  tmp_prefix=$(mktemp -u /tmp/cqst.XXXXXX)
  local url="$base/servlet/wxspeed?ran=$RANDOM.$RANDOM"
  local i j p f pids=() total_size=1073741824

  # 启动并发下载,每连接一个数据文件(每连接 1GiB,总基准 = 并发 × 1GiB)
  local total_cap
  total_cap=$((total_size * concurrency))
  for ((i=1; i<=concurrency; i++)); do
    curl -s --max-time "$duration" -o "$tmp_prefix.$i" "$url" 2>/dev/null &
    pids+=($!)
  done

  # 注意:本函数在命令替换 $(...) 中运行,stdout 是管道(被捕获),
  # 实时刷新走 stderr,因此用 -t 2 检测 stderr 是否为终端
  local live=0
  [[ -t 2 || -n "${FORCE_LIVE:-}" ]] && live=1

  # 实时监控:先采样 → 刷新 → 再检测完成(保证最后一帧是真实进度)
  local start_ts prev_ts cur_ts prev_bytes=0 cur_bytes=0 alive shown=0
  start_ts=$(date +%s); prev_ts=$start_ts

  while :; do
    alive=0
    for p in "${pids[@]}"; do kill -0 "$p" 2>/dev/null && alive=1; done
    # 采样当前文件大小
    cur_bytes=0
    for ((i=1; i<=concurrency; i++)); do
      f="$tmp_prefix.$i"
      [[ -f "$f" ]] && cur_bytes=$((cur_bytes + $(stat -c %s "$f" 2>/dev/null || echo 0)))
    done
    if [[ $live -eq 1 && $alive -eq 1 ]]; then
      cur_ts=$(date +%s)
      if (( cur_ts > prev_ts )); then
        local inst cur_avg
        inst=$(awk -v b="$((cur_bytes-prev_bytes))" -v t="$((cur_ts-prev_ts))" 'BEGIN{printf "%.1f", b*8/t/1e6}')
        cur_avg=$(awk -v b="$cur_bytes" -v t="$((cur_ts-start_ts))" 'BEGIN{if(t>0) printf "%.1f", b*8/t/1e6; else print 0}')
        render_progress "$label" "$((cur_ts-start_ts))" "$duration" "$cur_bytes" "$inst" "$cur_avg"
        shown=1
        prev_ts=$cur_ts; prev_bytes=$cur_bytes
      fi
    fi
    [[ $alive -eq 0 ]] && break
    sleep 0.5
  done

  # 下载结束(超时或拉满数据流):等所有 curl 退出后,补一帧最终进度
  for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done
  if [[ $live -eq 1 ]]; then
    local final_bytes=0 final_avg final_elapsed
    for ((i=1; i<=concurrency; i++)); do
      f="$tmp_prefix.$i"
      [[ -f "$f" ]] && final_bytes=$((final_bytes + $(stat -c %s "$f" 2>/dev/null || echo 0)))
    done
    final_elapsed=$(( $(date +%s) - start_ts ))
    final_avg=$(awk -v b="$final_bytes" -v t="$final_elapsed" 'BEGIN{if(t>0) printf "%.1f", b*8/t/1e6; else print 0}')
    # 提前拉满数据流视为完成(显示 100%),否则按时间进度
    if (( final_bytes >= total_cap )); then
      render_progress "$label" "$duration" "$duration" "$final_bytes" "$final_avg" "$final_avg"
    else
      render_progress "$label" "$final_elapsed" "$duration" "$final_bytes" "$final_avg" "$final_avg"
    fi
    printf '\033[K\n' >&2
    shown=1
  fi

  # 汇总字节数与耗时(实际墙钟时间)
  local end_ts bytes
  end_ts=$(date +%s)
  [[ $end_ts -le $start_ts ]] && end_ts=$((start_ts+1))
  bytes=0
  for ((i=1; i<=concurrency; i++)); do
    f="$tmp_prefix.$i"
    [[ -f "$f" ]] && bytes=$((bytes + $(stat -c %s "$f" 2>/dev/null || echo 0)))
  done
  rm -f "$tmp_prefix".*
  # 返回 "bytes seconds"
  printf '%s %s' "$bytes" "$((end_ts-start_ts))"
}

# ---------- 速率与展示 ----------
fmt_speed() {
  local bytes=$1 secs=$2
  awk -v b="$bytes" -v t="$secs" 'BEGIN{
    if (t<=0 || b<=0) { print "0.0 Mbps (0.00 MB/s)"; exit }
    mbps=b*8/t/1000000
    printf "%.2f Mbps (%.2f MB/s)", mbps, b/t/1000000
  }'
}

# 延迟颜色分级:≤10ms 绿 ≤30ms 黄 >30ms 红
ping_color() {
  local ms=$1
  if awk -v m="$ms" 'BEGIN{exit !(m<=10)}'; then echo "$C_GREEN"
  elif awk -v m="$ms" 'BEGIN{exit !(m<=30)}'; then echo "$C_YELLOW"
  else echo "$C_RED"; fi
}

# 宽带档位参考
tier_hint() {
  local mbps=$1
  awk -v m="$mbps" 'BEGIN{
    if (m>=850)   print "千兆(1000M)宽带"
    else if (m>=420) print "500M 宽带"
    else if (m>=230) print "300M 宽带"
    else if (m>=90)  print "100M 宽带"
    else if (m>=45)  print "50M 宽带"
    else print "低于 50M 或有异常"
  }'
}

# 达成率颜色与结论:≥95% 绿达标 ≥80% 黄基本达标 <80% 红差距较大
ratio_judge() {
  local ratio=$1
  if awk -v r="$ratio" 'BEGIN{exit !(r>=95)}'; then echo "$C_GREEN|✓ 与签约带宽相符"
  elif awk -v r="$ratio" 'BEGIN{exit !(r>=80)}'; then echo "$C_YELLOW|✓ 基本达标"
  else echo "$C_RED|✗ 与签约带宽差距较大"; fi
}

# ---------- 参数解析 ----------
while getopts "t:n:c:b:s:ph" opt; do
  case "$opt" in
    t) DURATION=$OPTARG ;;
    n) ROUNDS=$OPTARG ;;
    c) CONCURRENCY=$OPTARG ;;
    b) BANDWIDTH=$OPTARG ;;
    s) SERVER=$OPTARG ;;
    p) PING_ONLY=1 ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

# ---------- 主流程 ----------
echo
printf '%s────────────────────────────────────────────────────────────%s\n' "$C_GRAY" "$C_RESET"
printf '  %s重庆联通宽带测速%s  %scq-unicom-speedtest.sh%s\n' "$C_BOLD$C_WHITE" "$C_RESET" "$C_CYAN" "$C_RESET"
printf '  目标 %scesu.cqwin.com%s(官方节点·下行)   参数 %s 秒 × %s 轮 × %s 并发%s\n' \
  "$C_GREEN" "$C_RESET" "$DURATION" "$ROUNDS" "$CONCURRENCY" "$C_RESET"
printf '%s────────────────────────────────────────────────────────────%s\n' "$C_GRAY" "$C_RESET"
echo

# ---- 1. 宽带信息 ----
printf '%s── 宽带信息 ──────────────────────────────────────────%s\n' "$C_CYAN" "$C_RESET"
if [[ -n "$BANDWIDTH" ]]; then
  DB_CODE=$BANDWIDTH; CONF_CODE=""; REGION_NAME=""; ACCOUNT=""
  printf '  签约带宽  %s\n' "$(c "${DB_CODE}M" "$C_GREEN")(手动指定)"
else
  read -r DB_CODE CONF_CODE REGION_NAME ACCOUNT <<<"$(fetch_broadband_info)"
  if [[ -n "$DB_CODE" && "$DB_CODE" != "0" && "$DB_CODE" != "null" ]]; then
    printf '  签约带宽  %s%s\n' "$(c "${DB_CODE}M" "$C_GREEN")" "$(c "(${CONF_CODE}M 提速)" "$C_DIM")"
    [[ -n "$REGION_NAME" && "$REGION_NAME" != "null" ]] && printf '  所属区域  %s\n' "$(c "$REGION_NAME" "$C_WHITE")"
    if [[ -n "$ACCOUNT" && "$ACCOUNT" != "null" ]]; then
      printf '  宽带账号  %s\n' "$(c "${ACCOUNT:0:6}****${ACCOUNT: -3}" "$C_DIM")"
    fi
  else
    DB_CODE=""
    yellow "  未能获取签约带宽(可在非联通宽带环境下测速,或用 -b <兆> 指定)"
  fi
fi
echo

# ---- 2. 服务器列表 ----
printf '%s── 测速节点 ──────────────────────────────────────────%s\n' "$C_CYAN" "$C_RESET"
mapfile -t SERVERS < <(get_server_list)
if [[ ${#SERVERS[@]} -eq 0 ]]; then
  red "错误:未获取到任何测速服务器"; exit 1
fi
printf '  获取 %s 个测速节点 %s\n' "${#SERVERS[@]}" "$(c "✓" "$C_GREEN")"
echo

# ---- 3. 延迟测试 ----
if [[ -z "$SERVER" ]]; then
  printf '  %s延迟测试(每节点 3 次取最小)%s\n' "$C_DIM" "$C_RESET"
  declare -A PING_MS
  for s in "${SERVERS[@]}"; do
    ip=$(server_ip "$s")
    ms=$(ping_server "$s")
    PING_MS[$ip]=$ms
    if awk -v x="$ms" 'BEGIN{exit !(x<0)}'; then
      printf '    %-16s %s\n' "$ip" "$(c '超时/失败' "$C_RED")"
    else
      printf '    %-16s %s\n' "$ip" "$(c "${ms} ms" "$(ping_color "$ms")")"
    fi
  done
  # 选择延迟最低的服务器
  best_ip=""; best_ms=99999
  for s in "${SERVERS[@]}"; do
    ip=$(server_ip "$s")
    ms=${PING_MS[$ip]:-99999}
    if awk -v m="$ms" -v b="$best_ms" 'BEGIN{exit !(m>=0 && m<b)}'; then
      best_ms=$ms; best_ip=$ip
    fi
  done
  if [[ -z "$best_ip" || "$best_ms" =~ ^-1 ]]; then
    red "所有服务器延迟测试失败,请检查网络后重试"; exit 1
  fi
  for s in "${SERVERS[@]}"; do
    [[ "$(server_ip "$s")" == "$best_ip" ]] && SERVER_BASE="$s" && break
  done
  printf '\n  %s选中节点 %s(延迟 %s)%s\n\n' "$C_BOLD" "$best_ip" "$(c "${best_ms} ms" "$C_GREEN")" "$C_RESET"
else
  SERVER_BASE="http://$SERVER:8090/sts-base-node/"
  printf '  使用指定节点: %s\n\n' "$(c "$SERVER" "$C_WHITE")"
fi

# ---- 4. 只测延迟模式 ----
if [[ $PING_ONLY -eq 1 ]]; then
  echo; green "延迟测试完成(未进行下载测速)"; echo
  exit 0
fi

# ---- 5. 下载测速(多轮取最大) ----
printf '%s── 下载测速 ──────────────────────────────────────────%s\n' "$C_CYAN" "$C_RESET"
printf '  %s每轮最长 %s 秒,并发 %s 连接%s\n' "$C_DIM" "$DURATION" "$CONCURRENCY" "$C_RESET"
max_bytes=0; max_secs=0; max_mbps=0
sum_mbps=0
for ((r=1; r<=ROUNDS; r++)); do
  result=$(download_once "$SERVER_BASE" "$DURATION" "$CONCURRENCY" "$r/$ROUNDS")
  bytes=$(printf '%s' "$result" | cut -d' ' -f1)
  secs=$(printf '%s' "$result" | cut -d' ' -f2)
  mbps=$(awk -v b="$bytes" -v t="$secs" 'BEGIN{if(t>0) printf "%.2f", b*8/t/1e6; else print 0}')
  speed=$(fmt_speed "$bytes" "$secs")
  printf '  %s轮 %s/%s:%s 传输 %s MB,耗时 %s 秒 → %s\n' \
    "$C_DIM" "$r" "$ROUNDS" "$C_RESET" \
    "$(awk -v b="$bytes" 'BEGIN{printf "%.1f", b/1048576}')" \
    "$(awk -v t="$secs" 'BEGIN{printf "%.1f", t}')" \
    "$(c "$speed" "$C_GREEN")"
  if awk -v m="$mbps" -v mx="$max_mbps" 'BEGIN{exit !(m>mx)}'; then
    max_mbps=$mbps; max_bytes=$bytes; max_secs=$secs
  fi
  sum_mbps=$(awk -v s="$sum_mbps" -v m="$mbps" 'BEGIN{print s+m}')
done


# ---- 6. 结果汇总 ----
avg_mbps=$(awk -v s="$sum_mbps" -v r="$ROUNDS" 'BEGIN{printf "%.2f", s/r}')
echo
printf '%s────────────────────────────────── 测速结果 ──────────────────────────────────%s\n' "$C_GRAY" "$C_RESET"
printf '  %s%s  %s\n' "$(c '▸' "$C_DIM")" "$(c '最大下行速率' "$C_WHITE")" \
  "$(c "$(fmt_speed "$max_bytes" "$max_secs")" "$C_GREEN")"
printf '  %s%s  %s\n' "$(c '▸' "$C_DIM")" "$(c '平均下行速率' "$C_WHITE")" \
  "$(c "${avg_mbps} Mbps" "$C_CYAN")"
printf '  %s%s  %s\n' "$(c '▸' "$C_DIM")" "$(c '速率档位参考' "$C_WHITE")" \
  "$(c "$(tier_hint "$max_mbps")" "$C_YELLOW")"
if [[ -n "$DB_CODE" ]]; then
  ratio=$(awk -v m="$max_mbps" -v b="$DB_CODE" 'BEGIN{if(b>0) printf "%.1f", m/b*100; else print 0}')
  IFS='|' read -r ratio_color ratio_note <<<"$(ratio_judge "$ratio")"
  printf '  %s%s  %s\n' "$(c '▸' "$C_DIM")" "$(c '签约带宽' "$C_WHITE")" \
    "$(c "${DB_CODE}M" "$C_GREEN")"
  printf '  %s%s    %s %s\n' "$(c '▸' "$C_DIM")" "$(c '达成率' "$C_WHITE")" \
    "$(c "${ratio}%" "$ratio_color")" "$(c "$ratio_note" "$ratio_color")"
fi
printf '%s───────────────────────────────────────────────────────────────────────────%s\n' "$C_GRAY" "$C_RESET"
echo
