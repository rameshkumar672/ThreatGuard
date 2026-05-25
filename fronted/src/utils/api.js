// import axios from 'axios';

// const api = axios.create({
//   // baseURL: 'http://localhost:5000/api', // Since backend matches http://localhost:5000
//   baseURL: "https://threadguard-backends-production.up.railway.app/api",
//   headers: {
//     'Content-Type': 'application/json',
//   },
// });

// // Request interceptor to add token
// api.interceptors.request.use(
//   (config) => {
//     const token = localStorage.getItem('token');
//     if (token) {
//       config.headers.Authorization = `Bearer ${token}`; // Typical JWT format
//     }
//     return config;
//   },
//   (error) => Promise.reject(error)
// );

// export default api;
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:5000/api",
  headers: {
    "Content-Type": "application/json",
  },
});

// Request interceptor to add token only for protected routes
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("token");

    // Don't attach token for login/register routes
    const publicRoutes = [
      "/threatguard/login",
      "/threatguard/register",
      "/auth/login",
      "/auth/register"
    ];

    const isPublicRoute = publicRoutes.some((route) =>
      config.url.includes(route)
    );

    if (token && !isPublicRoute) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    return config;
  },
  (error) => Promise.reject(error)
);

export default api;
