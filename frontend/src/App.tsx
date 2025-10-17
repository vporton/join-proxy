import { useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import { LoginButton } from './components/LoginButton'

function App() {
  const [count, setCount] = useState(0)

  return (
    <>
      <div>
        <LoginButton/>
      </div>
      <h1>Control Managed Join Proxy</h1>
      <div>
        
      </div>
    </>
  )
}

export default App
