import { useState } from 'react'
import  { BrowserRouter, Route, Routes, NavLink } from 'react-router-dom'
import './App.css'
import { LoginButton } from './components/LoginButton'
import { Home } from './pages/Home'
import 'bootstrap/dist/css/bootstrap.min.css';
import { Container, Nav, Navbar } from 'react-bootstrap'

function App() {
  return (
    <Container id="main">
      <p>
        <LoginButton/>
      </p>
      <h1>Control Managed Join Proxy</h1>
      <div>
        <BrowserRouter>
          <Nav>
            <Navbar>
              <Nav.Link to="/" as={NavLink}>Home</Nav.Link>
              <Nav.Link to="/edit" as={NavLink}>Edit</Nav.Link>
            </Navbar>
          </Nav>
          <Routes>
            <Route path="/" element={<Home/>} />
          </Routes>
        </BrowserRouter>
      </div>
    </Container>
  )
}

export default App
