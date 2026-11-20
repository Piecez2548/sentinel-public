import { useEffect, useRef } from 'react';
import * as echarts from 'echarts/core';
import { BarChart, LineChart, PieChart, ScatterChart } from 'echarts/charts';
import { GridComponent, LegendComponent, MarkLineComponent, TooltipComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';

echarts.use([LineChart, BarChart, PieChart, ScatterChart, GridComponent, TooltipComponent, LegendComponent, MarkLineComponent, CanvasRenderer]);

export const C = {
  text: '#8c8ba0',
  line: '#2a2937',
  accent: '#8b5cf6',
  accent2: '#38bdf8',
  ok: '#22c55e',
  warn: '#eab308',
  bad: '#ef4444',
  orange: '#f97316',
  tooltip: { backgroundColor: '#1c1b26', borderColor: '#2a2937', textStyle: { color: '#e7e6f0' } },
};

export const baseAxis = {
  axisLabel: { color: C.text },
  axisLine: { lineStyle: { color: C.line } },
  splitLine: { lineStyle: { color: C.line, type: 'dashed' as const } },
};

export function Chart({ option, height = 220 }: { option: echarts.EChartsCoreOption; height?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    chart.current = echarts.init(ref.current);
    const ro = new ResizeObserver(() => chart.current?.resize());
    ro.observe(ref.current);
    return () => {
      ro.disconnect();
      chart.current?.dispose();
      chart.current = null;
    };
  }, []);

  useEffect(() => {
    chart.current?.setOption({ animation: false, tooltip: { ...C.tooltip }, ...option }, true);
  }, [option]);

  return <div ref={ref} style={{ height }} className="w-full" />;
}
