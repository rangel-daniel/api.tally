import { Router } from 'express';

import { createPoll, getPoll, getPolls, rmPoll } from '../controllers/poll';
import { verifyJwt } from '../middleware/verifyJwt';

const router = Router();

router.route('/').post(verifyJwt, createPoll).get(verifyJwt, getPolls);

router.route('/rm/:pid').post(verifyJwt, rmPoll);

router.route('/:pid').get(getPoll);

export default router;
