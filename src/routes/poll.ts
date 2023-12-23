import { Router } from 'express';

import {
    createPoll,
    getPollById,
} from '../controllers/poll';

const router = Router();

router.route('/').post(createPoll);


router.route('/:_id').get(getPollById);

export default router;
