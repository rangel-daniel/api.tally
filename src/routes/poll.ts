import { Router } from 'express';

import {
    createPoll,
} from '../controllers/poll';

const router = Router();

router.route('/').post(createPoll);

export default router;
