'use client';

import { clsx } from 'clsx';

interface SeverityBadgeProps {
  severity: string | null;
  size?: 'sm' | 'md';
}

export default function SeverityBadge({ severity, size = 'md' }: SeverityBadgeProps) {
  const normalizedSeverity = (severity || 'unknown').toLowerCase();

  const classes = clsx(
    'inline-flex items-center font-medium rounded-full',
    size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-sm',
    {
      'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200': normalizedSeverity === 'critical',
      'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200': normalizedSeverity === 'high',
      'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200': normalizedSeverity === 'medium',
      'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200': normalizedSeverity === 'low',
      'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200': normalizedSeverity === 'unknown',
    }
  );

  return <span className={classes}>{severity || 'Unknown'}</span>;
}
