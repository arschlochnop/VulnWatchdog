#!/bin/bash

# ==========================================
# VulnWatchdog 本地快速测试脚本
# ==========================================
# 用途：快速验证新功能是否稳定运行
#
# 测试内容：
# 1. 监控模块集成
# 2. 临时文件清理机制
# 3. GPT解析鲁棒性
# 4. Commit SHA更新检测
#
# 使用方法：
#   chmod +x test_local.sh
#   ./test_local.sh
# ==========================================

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}VulnWatchdog 本地测试${NC}"
echo -e "${BLUE}=========================================${NC}"

# 1. 检查 Python 环境
echo -e "\n${YELLOW}[1/6] 检查 Python 环境...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}✓ Python 已安装: $PYTHON_VERSION${NC}"
else
    echo -e "${RED}✗ 未找到 Python3${NC}"
    exit 1
fi

# 2. 检查虚拟环境
echo -e "\n${YELLOW}[2/6] 检查虚拟环境...${NC}"
if [ -d ".venv" ]; then
    echo -e "${GREEN}✓ 虚拟环境已存在${NC}"
else
    echo -e "${YELLOW}! 虚拟环境不存在，正在创建...${NC}"
    python3 -m venv .venv
    echo -e "${GREEN}✓ 虚拟环境创建成功${NC}"
fi

# 激活虚拟环境
echo -e "${YELLOW}激活虚拟环境...${NC}"
source .venv/bin/activate

# 3. 安装依赖
echo -e "\n${YELLOW}[3/6] 检查依赖...${NC}"
pip install -q -r requirements.txt
echo -e "${GREEN}✓ 依赖已安装${NC}"

# 4. 检查配置文件
echo -e "\n${YELLOW}[4/6] 检查配置文件...${NC}"
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}! 未找到 .env 文件${NC}"
    echo -e "${YELLOW}  正在从 .env.test 创建默认配置...${NC}"
    cp .env.test .env
    echo -e "${GREEN}✓ 已创建 .env 文件${NC}"
    echo -e "${YELLOW}  ⚠️  请编辑 .env 文件，配置必要的 API 密钥${NC}"
    echo ""
    echo -e "${BLUE}最小测试配置（无需外部服务）：${NC}"
    echo "  在 config.py 中设置："
    echo "    ENABLE_GPT = False"
    echo "    ENABLE_SEARCH = False"
    echo "    ENABLE_NOTIFY = False"
    echo ""
    echo -e "${BLUE}完整测试配置（需要 GPT API）：${NC}"
    echo "  在 .env 中配置："
    echo "    GPT_SERVER_URL=https://your-gpt-server/v1/chat/completions"
    echo "    GPT_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    echo ""
    read -p "按回车键继续（确保已配置）..."
else
    echo -e "${GREEN}✓ 配置文件已存在${NC}"
fi

# 5. 显示当前配置
echo -e "\n${YELLOW}[5/6] 当前配置状态...${NC}"
echo "查看 config.py 中的功能开关："
grep "^ENABLE_" config.py | while read line; do
    echo "  $line"
done

# 6. 运行测试
echo -e "\n${YELLOW}[6/6] 开始运行测试...${NC}"
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}测试程序: test_main.py${NC}"
echo -e "${BLUE}处理数量: 前3个仓库（快速测试）${NC}"
echo -e "${BLUE}=========================================${NC}\n"

# 运行测试主程序
python3 test_main.py

# 测试结果
TEST_EXIT_CODE=$?

echo ""
echo -e "${BLUE}=========================================${NC}"
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ 测试完成${NC}"
else
    echo -e "${RED}✗ 测试失败（退出码: $TEST_EXIT_CODE）${NC}"
fi
echo -e "${BLUE}=========================================${NC}"

# 显示生成的文件
echo -e "\n${YELLOW}生成的文件：${NC}"
if [ -f "test_monitor_result.json" ]; then
    echo -e "  ${GREEN}✓${NC} test_monitor_result.json - 监控数据"
fi

if [ -d "data" ]; then
    REPORT_COUNT=$(find data -name "*.md" -type f 2>/dev/null | wc -l | tr -d ' ')
    if [ "$REPORT_COUNT" -gt 0 ]; then
        echo -e "  ${GREEN}✓${NC} data/ - 分析报告 ($REPORT_COUNT 个)"
        echo -e "    最新报告："
        find data -name "*.md" -type f -print0 | xargs -0 ls -lt | head -3 | awk '{print "      " $9}'
    fi
fi

# 检查临时文件
echo -e "\n${YELLOW}临时文件检查：${NC}"
TEMP_COUNT=$(find /tmp -name "vulnwatchdog_*" -type d 2>/dev/null | wc -l | tr -d ' ')
if [ "$TEMP_COUNT" -eq 0 ]; then
    echo -e "  ${GREEN}✓${NC} 无临时文件残留（清理机制正常）"
else
    echo -e "  ${YELLOW}!${NC} 发现 $TEMP_COUNT 个临时目录（可能需要手动清理）"
    find /tmp -name "vulnwatchdog_*" -type d 2>/dev/null | head -3
fi

# 显示监控摘要
if [ -f "test_monitor_result.json" ]; then
    echo -e "\n${YELLOW}监控摘要：${NC}"
    if command -v jq &> /dev/null; then
        cat test_monitor_result.json | jq -r '
            "  运行时长: \(.runtime.formatted)",
            "  CVE总数: \(.discovery.total_cves)",
            "  仓库总数: \(.discovery.total_repos)",
            "  新仓库: \(.processing.new)",
            "  更新仓库: \(.processing.updated)",
            "  跳过: \(.processing.skipped)",
            "  成功率: \(.processing.success_rate)",
            "  GPT调用: \(.gpt.calls) 次",
            "  错误数: \(.errors.total)"
        '
    else
        echo -e "  ${YELLOW}提示: 安装 jq 可以更好地查看监控数据${NC}"
        echo -e "  ${YELLOW}brew install jq${NC}"
    fi
fi

echo -e "\n${BLUE}=========================================${NC}"
echo -e "${GREEN}测试脚本执行完成！${NC}"
echo -e "${BLUE}=========================================${NC}"

# 提示下一步
echo -e "\n${YELLOW}下一步操作建议：${NC}"
echo "  1. 查看日志输出，检查是否有错误"
echo "  2. 检查 test_monitor_result.json 查看详细监控数据"
echo "  3. 查看 data/ 目录下生成的分析报告"
echo "  4. 如果测试通过，可以运行完整版本: python main.py"
echo ""

exit $TEST_EXIT_CODE
