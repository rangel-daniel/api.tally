import { Router } from 'express';
import { registerUser, activateAccount, changePassword, forgotPassword } from '../controllers/auth';

const router = Router();

router.route('/')
	.post(registerUser);
	
router.route('/forgot-password')
	.post(forgotPassword);

router.route('/activate/:token')
	.get(activateAccount);

router.route('/password/:token')
	.get(changePassword)
	.post(changePassword);


export default router;
