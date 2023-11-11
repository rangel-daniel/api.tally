import { Router } from 'express';
import { registerUser } from './controllers/authController';

const router = Router();

router.route('/')
	.post(registerUser);

export default router;
