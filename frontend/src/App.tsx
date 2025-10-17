import  { BrowserRouter, Route, Routes, NavLink } from 'react-router-dom'
import './App.css'
import { LoginButton } from './components/LoginButton'
import { Home } from './pages/Home'
import 'bootstrap/dist/css/bootstrap.min.css';
import { Container, Nav, Navbar } from 'react-bootstrap'
import { Configs } from './pages/Configs';

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
              <Nav.Link to="/config" as={NavLink}>Configs</Nav.Link>
            </Navbar>
          </Nav>
          <Routes>
            <Route path="/" element={<Home/>} />
            <Route path="/config" element={<Configs/>} />
          </Routes>
        </BrowserRouter>
      </div>
    </Container>
  )
}

export default App
