import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import { ProtectedRoute, GuestOnlyRoute } from "./components/auth/RouteGuards";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Chatroom from "./components/Chatroom";

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route
            path="/login"
            element={
              <GuestOnlyRoute>
                <Login />
              </GuestOnlyRoute>
            }
          />
          <Route
            path="/register"
            element={
              <GuestOnlyRoute>
                <Register />
              </GuestOnlyRoute>
            }
          />
          <Route
            path="/chat"
            element={
              <ProtectedRoute>
                <Chatroom />
              </ProtectedRoute>
            }
          />
          <Route path="/" element={<Navigate replace to="/chat" />} />
          <Route path="*" element={<Navigate replace to="/chat" />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
