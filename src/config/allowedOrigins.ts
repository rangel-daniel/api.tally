import { CorsOptions } from 'cors';
const allowedOrigins = ['http://localhost:5173', 'https://tally-app.live'];

export const corsOptions: CorsOptions = {
    origin: allowedOrigins,
    credentials: true,
};
