import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';

import { setupSwagger } from './swagger'

import userRoutes from './routes/user.routes';
import authRoutes from './routes/auth.routes';

import clinicalHistoryRoutes from './routes/clinicalhistory.routes';
import invoiceRoutes from './routes/invoices.routes';

import authMiddleware from './middleware/auth.middleware';
import errorHandler from './middleware/errorHandler';





dotenv.config();
const app = express();

// Permitir cualquier origen
app.use(cors())

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

setupSwagger(app);


app.use('/users', userRoutes);
app.use('/auth', authRoutes);

// Rutas protegidas
app.use('/clinical-history', authMiddleware, clinicalHistoryRoutes);
app.use('/invoices', authMiddleware, invoiceRoutes);

// Global error handler
app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📖 Swagger UI: http://localhost:${PORT}/api-docs`)
});







export default app;
