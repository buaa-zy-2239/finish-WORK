"""
统计工具模块 - 顶会级统计严谨性支持

提供置信区间计算、方差分析、显著性检验等功能
符合IEEE/ACM统计标准
"""

import numpy as np
from scipy import stats
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
import math


@dataclass
class StatisticalSummary:
    """统计摘要（顶会标准格式）"""
    mean: float
    std: float
    sem: float  # 标准误
    ci_95_lower: float
    ci_95_upper: float
    ci_95_margin: float  # 误差范围（用于误差棒）
    n_samples: int
    min_val: float
    max_val: float
    median: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "mean": round(self.mean, 4),
            "std": round(self.std, 4),
            "sem": round(self.sem, 4),
            "ci_95": f"{round(self.mean, 2)} ± {round(self.ci_95_margin, 2)}",
            "ci_95_lower": round(self.ci_95_lower, 4),
            "ci_95_upper": round(self.ci_95_upper, 4),
            "ci_95_margin": round(self.ci_95_margin, 4),
            "n_samples": self.n_samples,
            "min": round(self.min_val, 4),
            "max": round(self.max_val, 4),
            "median": round(self.median, 4),
        }
    
    def format_with_ci(self, precision: int = 2) -> str:
        """顶会标准格式: mean ± CI_margin"""
        return f"{self.mean:.{precision}f} ± {self.ci_95_margin:.{precision}f}"


class StatisticalAnalyzer:
    """统计分析器 - 顶会级统计支持"""
    
    @staticmethod
    def calculate_summary(data: List[float], confidence: float = 0.95) -> StatisticalSummary:
        """
        计算统计摘要，包括置信区间
        
        Args:
            data: 样本数据列表
            confidence: 置信水平 (默认0.95 = 95%)
        
        Returns:
            StatisticalSummary对象
        """
        if not data or len(data) < 2:
            # 样本不足时返回NaN
            return StatisticalSummary(
                mean=float('nan'), std=float('nan'), sem=float('nan'),
                ci_95_lower=float('nan'), ci_95_upper=float('nan'),
                ci_95_margin=float('nan'), n_samples=len(data),
                min_val=float('nan'), max_val=float('nan'), median=float('nan')
            )
        
        data_array = np.array(data, dtype=float)
        n = len(data_array)
        mean = float(np.mean(data_array))
        std = float(np.std(data_array, ddof=1))  # 样本标准差
        sem = std / math.sqrt(n)  # 标准误
        
        # 计算置信区间 (使用t分布)
        alpha = 1 - confidence
        t_critical = stats.t.ppf(1 - alpha/2, df=n-1)
        margin = t_critical * sem
        
        ci_lower = mean - margin
        ci_upper = mean + margin
        
        return StatisticalSummary(
            mean=mean,
            std=std,
            sem=sem,
            ci_95_lower=ci_lower,
            ci_95_upper=ci_upper,
            ci_95_margin=margin,
            n_samples=n,
            min_val=float(np.min(data_array)),
            max_val=float(np.max(data_array)),
            median=float(np.median(data_array))
        )
    
    @staticmethod
    def pairwise_t_test(group1: List[float], group2: List[float]) -> Dict[str, Any]:
        """
        配对t检验 - 比较两组数据是否有显著差异
        
        Returns:
            {
                "t_statistic": float,
                "p_value": float,
                "significant": bool,  # p < 0.05?
                "effect_size": float,  # Cohen's d
            }
        """
        if len(group1) < 2 or len(group2) < 2:
            return {"error": "Insufficient samples"}
        
        t_stat, p_value = stats.ttest_ind(group1, group2, equal_var=False)
        
        # 计算Cohen's d (效应量)
        mean1, mean2 = np.mean(group1), np.mean(group2)
        std1, std2 = np.std(group1, ddof=1), np.std(group2, ddof=1)
        n1, n2 = len(group1), len(group2)
        
        # 合并标准差
        pooled_std = math.sqrt(((n1-1)*std1**2 + (n2-1)*std2**2) / (n1+n2-2))
        cohens_d = abs(mean1 - mean2) / pooled_std if pooled_std > 0 else 0
        
        return {
            "t_statistic": round(t_stat, 4),
            "p_value": round(p_value, 4),
            "significant": p_value < 0.05,
            "significance_level": "***" if p_value < 0.001 else "**" if p_value < 0.01 else "*" if p_value < 0.05 else "ns",
            "effect_size": round(cohens_d, 4),
            "effect_interpretation": (
                "large" if cohens_d >= 0.8 else
                "medium" if cohens_d >= 0.5 else
                "small" if cohens_d >= 0.2 else
                "negligible"
            ),
            "n1": n1,
            "n2": n2,
        }
    
    @staticmethod
    def anova_test(*groups: List[float]) -> Dict[str, Any]:
        """
        单因素方差分析 - 比较多组数据
        
        Returns:
            {
                "f_statistic": float,
                "p_value": float,
                "significant": bool,
                "eta_squared": float,  # 效应量
            }
        """
        if any(len(g) < 2 for g in groups):
            return {"error": "All groups must have at least 2 samples"}
        
        f_stat, p_value = stats.f_oneway(*groups)
        
        # 计算eta-squared (效应量)
        # SS_between / SS_total
        all_data = np.concatenate(groups)
        grand_mean = np.mean(all_data)
        
        ss_between = sum(len(g) * (np.mean(g) - grand_mean)**2 for g in groups)
        ss_total = np.sum((all_data - grand_mean)**2)
        eta_squared = ss_between / ss_total if ss_total > 0 else 0
        
        return {
            "f_statistic": round(f_stat, 4),
            "p_value": round(p_value, 4),
            "significant": p_value < 0.05,
            "significance_level": "***" if p_value < 0.001 else "**" if p_value < 0.01 else "*" if p_value < 0.05 else "ns",
            "eta_squared": round(eta_squared, 4),
            "effect_interpretation": (
                "large" if eta_squared >= 0.14 else
                "medium" if eta_squared >= 0.06 else
                "small" if eta_squared >= 0.01 else
                "negligible"
            ),
            "n_groups": len(groups),
            "total_n": len(all_data),
        }
    
    @staticmethod
    def aggregate_results_with_ci(
        results: List[Dict[str, Any]],
        metric_keys: List[str]
    ) -> Dict[str, StatisticalSummary]:
        """
        聚合多次运行的结果，计算统计摘要
        
        Args:
            results: 多次运行的结果字典列表
            metric_keys: 需要聚合的指标键名
        
        Returns:
            每个指标的StatisticalSummary
        """
        summaries = {}
        
        for key in metric_keys:
            values = []
            for r in results:
                # 支持嵌套键 (如 "authentication.success_rate")
                parts = key.split(".")
                val = r
                for p in parts:
                    if isinstance(val, dict):
                        val = val.get(p)
                    else:
                        val = None
                        break
                
                if val is not None and isinstance(val, (int, float)):
                    values.append(float(val))
            
            if values:
                summaries[key] = StatisticalAnalyzer.calculate_summary(values)
            else:
                summaries[key] = None
        
        return summaries


# 顶会标准种子生成器
def generate_statistical_seeds(base_seed: int, n_runs: int = 30) -> List[int]:
    """
    生成统计严谨性要求的独立随机种子
    
    使用线性同余生成器确保种子间的独立性
    
    Args:
        base_seed: 基础种子
        n_runs: 运行次数 (默认30，符合顶会标准)
    
    Returns:
        独立种子列表
    """
    seeds = []
    a = 1103515245  # LCG乘数
    c = 12345       # LCG增量
    m = 2**31       # 模数
    
    current = base_seed
    for _ in range(n_runs):
        current = (a * current + c) % m
        seeds.append(current)
    
    return seeds


# 便捷函数
def quick_ci(data: List[float]) -> str:
    """快速计算并格式化置信区间"""
    summary = StatisticalAnalyzer.calculate_summary(data)
    return summary.format_with_ci()


def compare_protocols(
    protocol_a_results: List[float],
    protocol_b_results: List[float],
    protocol_a_name: str = "Protocol A",
    protocol_b_name: str = "Protocol B"
) -> Dict[str, Any]:
    """
    比较两个协议的实验结果（顶会标准格式）
    
    Returns:
        完整的比较报告
    """
    summary_a = StatisticalAnalyzer.calculate_summary(protocol_a_results)
    summary_b = StatisticalAnalyzer.calculate_summary(protocol_b_results)
    t_test = StatisticalAnalyzer.pairwise_t_test(protocol_a_results, protocol_b_results)
    
    return {
        protocol_a_name: summary_a.to_dict(),
        protocol_b_name: summary_b.to_dict(),
        "comparison": {
            "absolute_difference": round(summary_b.mean - summary_a.mean, 4),
            "relative_improvement": round((summary_b.mean - summary_a.mean) / summary_a.mean * 100, 2) if summary_a.mean != 0 else None,
            "t_test": t_test,
            "conclusion": (
                f"{protocol_b_name} significantly outperforms {protocol_a_name}"
                if t_test.get("significant") and summary_b.mean > summary_a.mean
                else f"{protocol_a_name} significantly outperforms {protocol_b_name}"
                if t_test.get("significant") and summary_a.mean > summary_b.mean
                else "No significant difference between protocols"
            ),
        }
    }
