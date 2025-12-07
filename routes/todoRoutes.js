/**
 * Todo Routes
 * All routes require authentication
 */

const express = require('express');
const router = express.Router();

const todoController = require('../controllers/todoController');
const { authenticate } = require('../middleware/auth');
const { validateTodo, validateObjectId } = require('../middleware/validation');

// All todo routes require authentication
router.use(authenticate);

// CRUD operations
router.get('/', todoController.getTodos);
router.post('/', validateTodo, todoController.createTodo);
router.put('/:id', validateObjectId, validateTodo, todoController.updateTodo);
router.delete('/:id', validateObjectId, todoController.deleteTodo);

module.exports = router;
