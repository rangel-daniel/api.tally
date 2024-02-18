import { Router } from 'express';
import {
    signup,
    signin,
    activateAccount,
    changePasswordWithToken,
    forgotPassword,
    refresh,
    signout,
    deleteAccount,
    resendEmail,
    authenticate,
} from '../controllers/auth';
import { loginLimiter } from '../middleware/loginLimiter';
import { verifyJwt } from '../middleware/verifyJwt';

const router = Router();

router.route('/').get(refresh).post(loginLimiter, signin).delete(signout);
router.route('/signup').post(signup).patch(verifyJwt, authenticate);

router.route('/delete-account').delete(verifyJwt, deleteAccount);

router.route('/forgot-password').post(forgotPassword);
router.route('/password').patch(changePasswordWithToken);

router.route('/resend-email').post(resendEmail);
router.route('/activate').patch(activateAccount);

export default router;
