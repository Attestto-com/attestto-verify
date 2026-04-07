/// <reference types="vite/client" />

declare module '*.pem?raw' {
  const content: string
  export default content
}

declare module '*?raw' {
  const content: string
  export default content
}
