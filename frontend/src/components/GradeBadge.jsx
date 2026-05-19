import { getGradeColor } from '../utils'

export default function GradeBadge({ grade, size = 'md' }) {
  const n = Number(grade)
  const display = n >= 1 && n <= 10 ? n : '—'
  const sizes = {
    sm: 'w-8 h-8 text-sm',
    md: 'w-10 h-10 text-base',
    lg: 'w-14 h-14 text-xl font-bold',
  }
  return (
    <span
      className={`inline-flex items-center justify-center rounded-full font-bold ${sizes[size]} ${getGradeColor(display)}`}
      title={`Nota ${display} de 10`}
    >
      {display}
    </span>
  )
}
