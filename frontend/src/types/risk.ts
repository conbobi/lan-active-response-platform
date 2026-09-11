// src/types/risk.ts

export interface RiskScore {
  id: string;
  agent_id: string;
  score: number;
  smoothed_score: number;   // Điểm đã làm mượt (EMA)
  factors: Record<string, any>;
  timestamp: string;
}

export interface FactorDetail {
  rule_name: string;
  points: number;
  reason: string;
}

// Helper: parse factors JSON thành mảng
export function parseFactors(factors: Record<string, any>): FactorDetail[] {
  if (!factors || typeof factors !== 'object') return [];
  return Object.entries(factors)
    .filter(([key, val]) => 
      key !== 'total_score' && (typeof val === 'number' ? val > 0 : val !== null && val !== '')
    )
    .map(([key, val]) => ({
      rule_name: key,
      points: typeof val === 'number' ? val : 0,
      reason: typeof val === 'string' ? val : JSON.stringify(val),
    }))
    .sort((a, b) => b.points - a.points);
}
