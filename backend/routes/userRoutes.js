import express from 'express';
import { createUsers, loginUser, logoutCurrentUser, getAllUsers, getCurrentUserProfile, updateCurrentUserProfile } from '../controllers/userController.js';
import { authenticate, authorizedAdmin } from '../middlewares/authMiddleware.js';
const router = express.Router();
router.route('/').post(createUsers).get(authenticate, authorizedAdmin, getAllUsers);
router.post('/auth', loginUser);
router.post('/logout', logoutCurrentUser);
router.route("/profile").get(authenticate, getCurrentUserProfile).put(authenticate, updateCurrentUserProfile);


export default router;
