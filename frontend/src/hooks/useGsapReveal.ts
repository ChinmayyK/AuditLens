import { useLayoutEffect, useRef } from 'react'
import gsap from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'

gsap.registerPlugin(ScrollTrigger)

export function useGsapReveal() {
  const containerRef = useRef<HTMLDivElement | null>(null)

  useLayoutEffect(() => {
    if (!containerRef.current) return

    const ctx = gsap.context(() => {
      const nodes = gsap.utils.toArray<HTMLElement>('[data-reveal]')
      nodes.forEach((node, index) => {
        gsap.fromTo(
          node,
          { autoAlpha: 0, y: 28 },
          {
            autoAlpha: 1,
            y: 0,
            duration: 0.65,
            ease: 'power3.out',
            delay: index * 0.03,
            scrollTrigger: {
              trigger: node,
              start: 'top 88%',
              once: true,
            },
          }
        )
      })
    }, containerRef)

    ScrollTrigger.refresh()
    return () => ctx.revert()
  }, [])

  return containerRef
}
