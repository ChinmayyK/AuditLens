export interface ApiErrorLike {
  message?: string
  response?: {
    status?: number
    data?: {
      detail?: string
    }
  }
}

export function asApiError(error: unknown): ApiErrorLike {
  return typeof error === 'object' && error !== null ? error as ApiErrorLike : {}
}

export function getApiErrorMessage(error: unknown, fallback: string) {
  return asApiError(error).response?.data?.detail || fallback
}
