import { useState } from 'react'
import  { BrowserRouter, Route, Routes } from 'react-router-dom'
import './App.css'
import { LoginButton } from './components/LoginButton'
import { Home } from './pages/Home'

function App() {
  return (
    <>
      <div>
        <LoginButton/>
      </div>
      <h1>Control Managed Join Proxy</h1>
      <div>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Home/>} />
          </Routes>
        </BrowserRouter>
      </div>
    </>
  )
}

export default App
