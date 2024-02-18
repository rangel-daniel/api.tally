import { Router } from 'express';
import { getUser, updateEmail, updateName, updatePassword } from '../controllers/user';
import { verifyJwt } from '../middleware/verifyJwt';

const router = Router();

router.route('/').get(verifyJwt, getUser);
router.route('/password').patch(verifyJwt, updatePassword);
router.route('/email').patch(verifyJwt, updateEmail);
router.route('/name').patch(verifyJwt, updateName);

export default router;
