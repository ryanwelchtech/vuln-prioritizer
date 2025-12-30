'use client';

import { useMemo } from 'react';

interface RiskGaugeProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

export default function RiskGauge({ score, size = 'md', showLabel = true }: RiskGaugeProps) {
  const { color, severity } = useMemo(() => {
    if (score >= 70) return { color: '#dc2626', severity: 'Critical' };
    if (score >= 40) return { color: '#ea580c', severity: 'High' };
    if (score >= 20) return { color: '#ca8a04', severity: 'Medium' };
    return { color: '#16a34a', severity: 'Low' };
  }, [score]);

  const dimensions = {
    sm: { width: 60, height: 60, strokeWidth: 6, fontSize: 12 },
    md: { width: 100, height: 100, strokeWidth: 8, fontSize: 16 },
    lg: { width: 150, height: 150, strokeWidth: 10, fontSize: 24 },
  };

  const { width, height, strokeWidth, fontSize } = dimensions[size];
  const radius = (width - strokeWidth) / 2;
  const circumference = radius * Math.PI;
  const progress = (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <svg width={width} height={height / 2 + 10} viewBox={`0 0 ${width} ${height / 2 + 10}`}>
        {/* Background arc */}
        <path
          d={`M ${strokeWidth / 2} ${height / 2} A ${radius} ${radius} 0 0 1 ${width - strokeWidth / 2} ${height / 2}`}
          fill="none"
          stroke="#e5e7eb"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />
        {/* Progress arc */}
        <path
          d={`M ${strokeWidth / 2} ${height / 2} A ${radius} ${radius} 0 0 1 ${width - strokeWidth / 2} ${height / 2}`}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference - progress}
          style={{ transition: 'stroke-dashoffset 0.5s ease-in-out' }}
        />
        {/* Score text */}
        <text
          x={width / 2}
          y={height / 2 - 5}
          textAnchor="middle"
          fontSize={fontSize}
          fontWeight="bold"
          fill={color}
        >
          {Math.round(score)}
        </text>
      </svg>
      {showLabel && (
        <span
          className="text-sm font-medium mt-1"
          style={{ color }}
        >
          {severity}
        </span>
      )}
    </div>
  );
}
