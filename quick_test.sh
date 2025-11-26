#!/bin/bash
# VulnWatchdog 快速测试脚本

echo "🚀 VulnWatchdog 优化功能快速测试"
echo "================================"
echo ""

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 测试计数
PASSED=0
FAILED=0

# 检查虚拟环境
echo "📦 检查环境..."
if [ ! -d ".venv" ]; then
    echo -e "${RED}❌ 虚拟环境不存在${NC}"
    echo "   请先创建: python -m venv .venv"
    exit 1
fi

# 激活虚拟环境
source .venv/bin/activate || {
    echo -e "${RED}❌ 无法激活虚拟环境${NC}"
    exit 1
}

echo -e "${GREEN}✅ 虚拟环境已激活${NC}"
echo ""

# 测试1: 更新检测逻辑
echo "🧪 测试1: 更新检测逻辑"
echo "----------------------"
if python test_update_logic.py > /dev/null 2>&1; then
    echo -e "${GREEN}✅ 通过${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ 失败${NC}"
    ((FAILED++))
fi
echo ""

# 测试2: 临时文件清理
echo "🧪 测试2: 临时文件清理机制"
echo "----------------------"
if python test_cleanup.py > /dev/null 2>&1; then
    echo -e "${GREEN}✅ 通过${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ 失败${NC}"
    ((FAILED++))
fi
echo ""

# 测试3: GPT解析
echo "🧪 测试3: GPT响应解析"
echo "----------------------"
if python test_gpt_parsing.py 2>&1 | grep -q "成功率: 100.0%"; then
    echo -e "${GREEN}✅ 通过 (8/8)${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ 失败${NC}"
    ((FAILED++))
fi
echo ""

# 测试4: 数据库字段检查
echo "🧪 测试4: 数据库字段"
echo "----------------------"
if sqlite3 vulns.db ".schema repositories" | grep -q "latest_commit_sha"; then
    echo -e "${GREEN}✅ 通过 (latest_commit_sha字段存在)${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ 失败 (字段不存在)${NC}"
    ((FAILED++))
fi
echo ""

# 测试5: 临时目录清理验证
echo "🧪 测试5: 临时目录检查"
echo "----------------------"
TEMP_COUNT=$(ls /tmp/vulnwatchdog_* 2>/dev/null | wc -l)
if [ "$TEMP_COUNT" -eq 0 ]; then
    echo -e "${GREEN}✅ 通过 (无残留临时目录)${NC}"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠️  警告 (发现 $TEMP_COUNT 个临时目录)${NC}"
    echo "   建议手动清理: rm -rf /tmp/vulnwatchdog_*"
    ((PASSED++))
fi
echo ""

# 测试6: 配置检查
echo "🧪 测试6: 配置检查"
echo "----------------------"
if grep -q "ENABLE_UPDATE_CHECK" config.py; then
    UPDATE_CHECK=$(grep "ENABLE_UPDATE_CHECK" config.py | grep -o "True\|False")
    echo -e "${GREEN}✅ 通过 (ENABLE_UPDATE_CHECK=$UPDATE_CHECK)${NC}"
    ((PASSED++))
else
    echo -e "${RED}❌ 失败 (配置缺失)${NC}"
    ((FAILED++))
fi
echo ""

# 测试总结
echo "================================"
echo "📊 测试总结"
echo "================================"
TOTAL=$((PASSED + FAILED))
echo "总计: $TOTAL 项测试"
echo -e "${GREEN}通过: $PASSED${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}失败: $FAILED${NC}"
fi

SUCCESS_RATE=$(echo "scale=1; $PASSED * 100 / $TOTAL" | bc)
echo "成功率: ${SUCCESS_RATE}%"
echo ""

# 额外信息
echo "💡 提示:"
echo "  - 完整测试文档: LOCAL_TEST_GUIDE.md"
echo "  - 查看优化详情: OPTIMIZATION_PHASE2.md"
echo "  - 使用指南: README_UPDATE_CHECK.md"
echo ""

# 数据库统计
echo "📊 数据库统计:"
echo "----------------------"
sqlite3 vulns.db "
SELECT
    '总记录数: ' || COUNT(*) || ' 条' as info FROM repositories
UNION ALL
SELECT
    '已填充SHA: ' || COUNT(latest_commit_sha) || ' 条' FROM repositories
UNION ALL
SELECT
    '待填充SHA: ' || (COUNT(*) - COUNT(latest_commit_sha)) || ' 条' FROM repositories
"
echo ""

# 提示数据迁移
SHA_COUNT=$(sqlite3 vulns.db "SELECT COUNT(latest_commit_sha) FROM repositories")
TOTAL_COUNT=$(sqlite3 vulns.db "SELECT COUNT(*) FROM repositories")

if [ "$SHA_COUNT" -lt "$TOTAL_COUNT" ]; then
    NEED_MIGRATE=$((TOTAL_COUNT - SHA_COUNT))
    echo -e "${YELLOW}⚠️  检测到 $NEED_MIGRATE 条记录缺少commit SHA${NC}"
    echo "   运行数据迁移: python scripts/migrate_commit_sha.py"
    echo "   预计耗时: $(echo "scale=1; $NEED_MIGRATE / 10 / 60" | bc) 分钟"
    echo ""
fi

# 退出码
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ 所有测试通过！${NC}"
    exit 0
else
    echo -e "${RED}❌ 有测试失败，请查看上方详情${NC}"
    exit 1
fi
