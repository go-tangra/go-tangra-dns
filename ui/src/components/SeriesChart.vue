<script setup lang="ts">
// A compact line chart of dashboard series drawn as SVG polylines (no inline
// styles: colours are theme classes, geometry is SVG attributes). The legend
// shows each series' latest value.
import { computed } from 'vue'
import type { DashboardSeries } from '@/api/types'
import { formatValue } from './format'

const props = defineProps<{ series: DashboardSeries[]; label: string; unit?: string | undefined }>()

const W = 300
const H = 100
const STROKES = ['stroke-primary', 'stroke-secondary', 'stroke-accent', 'stroke-info', 'stroke-warning', 'stroke-error', 'stroke-success']
const SWATCHES = ['bg-primary', 'bg-secondary', 'bg-accent', 'bg-info', 'bg-warning', 'bg-error', 'bg-success']

const bounds = computed(() => {
  const pts = props.series.flatMap((s) => s.points)
  if (pts.length === 0) return null
  const xs = pts.map((p) => p[0])
  const ys = pts.map((p) => p[1])
  const x0 = Math.min(...xs)
  const x1 = Math.max(...xs)
  const y1 = Math.max(...ys, 0)
  return { x0, dx: x1 - x0 || 1, dy: y1 || 1, y1 }
})

function polyline(s: DashboardSeries): string {
  const b = bounds.value
  if (!b) return ''
  return s.points.map((p) => `${(((p[0] - b.x0) / b.dx) * W).toFixed(1)},${(H - (p[1] / b.dy) * H).toFixed(1)}`).join(' ')
}

const legend = computed(() =>
  props.series.map((s, i) => ({
    name: s.labels.series ?? `series ${i + 1}`,
    swatch: SWATCHES[i % SWATCHES.length],
    latest: formatValue(s.points.length ? s.points[s.points.length - 1]?.[1] : undefined, props.unit),
  })),
)
</script>

<template>
  <div class="flex flex-col gap-2">
    <p v-if="!bounds" class="text-base-content/60 text-sm" data-test="chart-empty">No data in this window.</p>
    <svg v-else :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="none" class="h-32 w-full" role="img" :aria-label="label" data-test="chart">
      <line x1="0" :y1="H" :x2="W" :y2="H" class="stroke-base-300" stroke-width="1" />
      <polyline v-for="(s, i) in series" :key="i" :points="polyline(s)" fill="none" stroke-width="1.5" vector-effect="non-scaling-stroke" :class="STROKES[i % STROKES.length]" />
    </svg>
    <ul class="flex flex-wrap gap-x-4 gap-y-1 text-xs">
      <li v-for="l in legend" :key="l.name" class="flex items-center gap-1">
        <span class="inline-block size-2 rounded-full" :class="l.swatch" />
        <span>{{ l.name }}</span>
        <span class="text-base-content/70 tabular-nums">{{ l.latest }}</span>
      </li>
    </ul>
  </div>
</template>
