import { motion, useScroll, useSpring } from 'framer-motion'

export default function ScrollProgress() {
  const { scrollYProgress } = useScroll()
  const scaleX = useSpring(scrollYProgress, {
    stiffness: 120,
    damping: 24,
    mass: 0.25,
  })

  return (
    <motion.div
      className="pointer-events-none fixed left-0 top-0 z-[100] h-1 w-full origin-left bg-gradient-to-r from-primary via-accent-blue to-primary-light"
      style={{ scaleX }}
    />
  )
}
