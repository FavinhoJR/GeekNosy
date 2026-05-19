const GRADE_COLOR_SCALE = {
  10: 'bg-emerald-600 text-white',
  9: 'bg-emerald-500 text-white',
  8: 'bg-green-500 text-white',
  7: 'bg-green-400 text-white',
  6: 'bg-lime-500 text-white',
  5: 'bg-yellow-500 text-white',
  4: 'bg-amber-500 text-white',
  3: 'bg-orange-500 text-white',
  2: 'bg-red-400 text-white',
  1: 'bg-red-600 text-white',
}

export function getGradeColor(grade) {
  const n = Number(grade)
  if (n >= 1 && n <= 10) return GRADE_COLOR_SCALE[n]
  return GRADE_COLOR_SCALE[1]
}

export const STATUS_LABELS = {
  greater: { label: 'Mayor', class: 'text-emerald-600 bg-emerald-50' },
  less: { label: 'Menor', class: 'text-red-600 bg-red-50' },
  equal: { label: 'Igual', class: 'text-slate-600 bg-slate-100' },
}

export const RESPONSE_TYPE_LABELS = {
  main: 'Sitio principal (200)',
  redirect: 'Redirección',
  blocked: 'Bloqueado (403)',
  not_found: 'No encontrado (404)',
  success: 'Éxito',
  server_error: 'Error servidor',
  other: 'Otro',
  unknown: 'Desconocido',
}

export function formatDate(iso) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('es-ES', {
    dateStyle: 'short',
    timeStyle: 'short',
  })
}

export function formatDelta(delta) {
  if (delta == null) return '-'
  const sign = delta > 0 ? '+' : ''
  return `${sign}${delta.toFixed(1)}`
}
