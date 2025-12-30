'use client';

import { LucideIcon } from 'lucide-react';
import { clsx } from 'clsx';

interface StatsCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  color?: 'default' | 'critical' | 'high' | 'medium' | 'low';
}

export default function StatsCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  color = 'default',
}: StatsCardProps) {
  const iconColors = {
    default: 'text-blue-500 bg-blue-100 dark:bg-blue-900',
    critical: 'text-red-500 bg-red-100 dark:bg-red-900',
    high: 'text-orange-500 bg-orange-100 dark:bg-orange-900',
    medium: 'text-yellow-500 bg-yellow-100 dark:bg-yellow-900',
    low: 'text-green-500 bg-green-100 dark:bg-green-900',
  };

  return (
    <div className="card">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-500 dark:text-gray-400">{title}</p>
          <p className="mt-1 text-3xl font-semibold text-gray-900 dark:text-white">
            {value}
          </p>
          {subtitle && (
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              {subtitle}
            </p>
          )}
          {trend && (
            <p
              className={clsx(
                'mt-1 text-sm font-medium',
                trend.isPositive ? 'text-green-600' : 'text-red-600'
              )}
            >
              {trend.isPositive ? '↓' : '↑'} {Math.abs(trend.value)}%
            </p>
          )}
        </div>
        {Icon && (
          <div className={clsx('p-3 rounded-full', iconColors[color])}>
            <Icon className="h-6 w-6" />
          </div>
        )}
      </div>
    </div>
  );
}
