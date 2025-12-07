/**
 * Todo Controller
 * Handles CRUD operations for encrypted to-do items
 * 
 * Security flow:
 * 1. Create: Compute SHA-256 hash → Encrypt with AES-256-GCM → Store ciphertext + IV + authTag + hash
 * 2. Read: Decrypt with AES-256-GCM → Verify SHA-256 hash → Return plaintext only if valid
 * 3. Update: Re-encrypt and update integrity hash
 * 4. Delete: Remove from database
 */

const Todo = require('../models/Todo');
const { encrypt, decrypt } = require('../utils/crypto');
const { computeSHA256, verifyIntegrity } = require('../utils/hash');
const logger = require('../utils/logger');

/**
 * Get all todos for authenticated user
 * GET /api/todos
 */
const getTodos = async (req, res) => {
  try {
    const userId = req.userId;

    // Fetch all todos for this user
    const todos = await Todo.find({ userId }).sort({ createdAt: -1 });

    // Decrypt each todo and verify integrity
    const decryptedTodos = [];

    for (const todo of todos) {
      try {
        // Decrypt the content
        const plaintext = decrypt(
          todo.encryptedContent,
          todo.iv,
          todo.authTag
        );

        // Verify integrity hash
        const isIntegrityValid = verifyIntegrity(plaintext, todo.integrityHash);

        if (!isIntegrityValid) {
          // Integrity check failed - content was tampered with
          logger.securityEvent('Todo integrity check failed', {
            todoId: todo._id,
            userId: userId,
          });

          // Return a warning instead of the content
          decryptedTodos.push({
            id: todo._id,
            content: '[INTEGRITY VIOLATION - Content may have been tampered with]',
            tampered: true,
            createdAt: todo.createdAt,
            updatedAt: todo.updatedAt,
          });
        } else {
          // Integrity verified - return decrypted content
          decryptedTodos.push({
            id: todo._id,
            content: plaintext,
            tampered: false,
            createdAt: todo.createdAt,
            updatedAt: todo.updatedAt,
          });
        }
      } catch (error) {
        // Decryption failed (auth tag mismatch or other error)
        logger.securityEvent('Todo decryption failed', {
          todoId: todo._id,
          userId: userId,
          error: error.message,
        });

        decryptedTodos.push({
          id: todo._id,
          content: '[DECRYPTION FAILED - Content is corrupted]',
          tampered: true,
          error: error.message,
          createdAt: todo.createdAt,
          updatedAt: todo.updatedAt,
        });
      }
    }

    res.json({
      todos: decryptedTodos,
    });
  } catch (error) {
    logger.error('Get todos error:', error);
    res.status(500).json({
      error: 'Failed to retrieve todos',
    });
  }
};

/**
 * Create a new todo
 * POST /api/todos
 */
const createTodo = async (req, res) => {
  try {
    const userId = req.userId;
    const { content } = req.body;

    // Step 1: Compute integrity hash of plaintext
    const integrityHash = computeSHA256(content);

    // Step 2: Encrypt the content
    const { encryptedContent, iv, authTag } = encrypt(content);

    // Step 3: Store encrypted data
    const todo = await Todo.create({
      userId,
      encryptedContent,
      iv,
      authTag,
      integrityHash,
    });

    logger.info(`Todo created by user ${userId}`);

    // Return the plaintext content to client (don't make them decrypt)
    res.status(201).json({
      message: 'Todo created successfully',
      todo: {
        id: todo._id,
        content: content, // Return original plaintext
        createdAt: todo.createdAt,
        updatedAt: todo.updatedAt,
      },
    });
  } catch (error) {
    logger.error('Create todo error:', error);
    res.status(500).json({
      error: 'Failed to create todo',
      message: error.message,
    });
  }
};

/**
 * Update an existing todo
 * PUT /api/todos/:id
 */
const updateTodo = async (req, res) => {
  try {
    const userId = req.userId;
    const todoId = req.params.id;
    const { content } = req.body;

    // Find the todo and verify ownership
    const todo = await Todo.findOne({ _id: todoId, userId });

    if (!todo) {
      return res.status(404).json({
        error: 'Todo not found',
      });
    }

    // Re-encrypt with new content
    const integrityHash = computeSHA256(content);
    const { encryptedContent, iv, authTag } = encrypt(content);

    // Update the todo
    todo.encryptedContent = encryptedContent;
    todo.iv = iv;
    todo.authTag = authTag;
    todo.integrityHash = integrityHash;
    todo.updatedAt = Date.now();

    await todo.save();

    logger.info(`Todo ${todoId} updated by user ${userId}`);

    res.json({
      message: 'Todo updated successfully',
      todo: {
        id: todo._id,
        content: content,
        createdAt: todo.createdAt,
        updatedAt: todo.updatedAt,
      },
    });
  } catch (error) {
    logger.error('Update todo error:', error);
    res.status(500).json({
      error: 'Failed to update todo',
      message: error.message,
    });
  }
};

/**
 * Delete a todo
 * DELETE /api/todos/:id
 */
const deleteTodo = async (req, res) => {
  try {
    const userId = req.userId;
    const todoId = req.params.id;

    // Find and delete the todo (only if owned by user)
    const result = await Todo.deleteOne({ _id: todoId, userId });

    if (result.deletedCount === 0) {
      return res.status(404).json({
        error: 'Todo not found',
      });
    }

    logger.info(`Todo ${todoId} deleted by user ${userId}`);

    res.json({
      message: 'Todo deleted successfully',
    });
  } catch (error) {
    logger.error('Delete todo error:', error);
    res.status(500).json({
      error: 'Failed to delete todo',
    });
  }
};

module.exports = {
  getTodos,
  createTodo,
  updateTodo,
  deleteTodo,
};
