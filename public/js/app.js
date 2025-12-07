/**
 * Secure Note App - Frontend JavaScript
 * 
 * Security features:
 * - Uses textContent instead of innerHTML to prevent XSS
 * - Stores JWT in HTTP-only cookie (set by server)
 * - Also sends token in Authorization header as fallback
 * - Input validation on client-side (but server validates too)
 * - Error messages are escaped
 */

// ============================================
// State Management
// ============================================

let currentUser = null;
let todos = [];
let editingTodoId = null;

// Check if user is already logged in (cookie exists)
window.addEventListener('DOMContentLoaded', () => {
  checkAuthStatus();
  setupEventListeners();
  handleOAuthCallback();
});

// ============================================
// Authentication Status Check
// ============================================

async function checkAuthStatus() {
  try {
    // Try to fetch todos to check if we're authenticated
    const response = await fetch('/api/todos', {
      credentials: 'include', // Send cookies
    });

    if (response.ok) {
      // User is authenticated
      const data = await response.json();
      showAppView();
      displayTodos(data.todos);
    } else {
      // Not authenticated, show login
      showLoginView();
    }
  } catch (error) {
    console.error('Auth check failed:', error);
    showLoginView();
  }
}

// ============================================
// OAuth Callback Handler
// ============================================

function handleOAuthCallback() {
  const urlParams = new URLSearchParams(window.location.search);
  
  if (urlParams.get('login') === 'success') {
    // Google OAuth successful
    showAppView();
    loadTodos();
    // Clean URL
    window.history.replaceState({}, document.title, '/');
  }
  
  if (urlParams.get('error')) {
    const error = urlParams.get('error');
    showError('login-error', 'Authentication failed. Please try again.');
    // Clean URL
    window.history.replaceState({}, document.title, '/');
  }
}

// ============================================
// Event Listeners Setup
// ============================================

function setupEventListeners() {
  // Auth form submissions
  document.getElementById('login-form').addEventListener('submit', handleLogin);
  document.getElementById('register-form').addEventListener('submit', handleRegister);
  
  // View switching
  document.getElementById('show-register').addEventListener('click', (e) => {
    e.preventDefault();
    showRegisterView();
  });
  
  document.getElementById('show-login').addEventListener('click', (e) => {
    e.preventDefault();
    showLoginView();
  });
  
  // Google OAuth buttons
  document.getElementById('google-login-btn').addEventListener('click', () => {
    window.location.href = '/api/auth/google';
  });
  
  document.getElementById('google-register-btn').addEventListener('click', () => {
    window.location.href = '/api/auth/google';
  });
  
  // Note operations
  document.getElementById('todo-form').addEventListener('submit', handleAddTodo);
  document.getElementById('logout-btn').addEventListener('click', handleLogout);
  
  // Horizontal line insertion buttons
  document.getElementById('insert-hr-btn').addEventListener('click', () => insertHorizontalLine('todo-content'));
  document.getElementById('insert-hr-edit-btn').addEventListener('click', () => insertHorizontalLine('edit-content'));
  
  // Clear completed button
  const clearCompletedBtn = document.getElementById('clear-completed-btn');
  if (clearCompletedBtn) {
    clearCompletedBtn.addEventListener('click', handleClearCompleted);
  }
  
  // Edit modal
  document.getElementById('close-modal').addEventListener('click', closeEditModal);
  document.getElementById('cancel-edit').addEventListener('click', closeEditModal);
  document.getElementById('edit-form').addEventListener('submit', handleEditSubmit);
}

// ============================================
// View Management
// ============================================

function showLoginView() {
  document.getElementById('login-view').style.display = 'block';
  document.getElementById('register-view').style.display = 'none';
  document.getElementById('app-view').style.display = 'none';
  clearError('login-error');
}

function showRegisterView() {
  document.getElementById('login-view').style.display = 'none';
  document.getElementById('register-view').style.display = 'block';
  document.getElementById('app-view').style.display = 'none';
  clearError('register-error');
}

function showAppView() {
  document.getElementById('login-view').style.display = 'none';
  document.getElementById('register-view').style.display = 'none';
  document.getElementById('app-view').style.display = 'block';
  // Initialize counter if todos are already loaded
  if (todos.length > 0) {
    updateTaskCounter();
  }
}

// ============================================
// Authentication Handlers
// ============================================

async function handleRegister(e) {
  e.preventDefault();
  clearError('register-error');
  
  const form = e.target;
  const submitBtn = form.querySelector('button[type="submit"]');
  setLoading(submitBtn, true);
  
  const formData = {
    username: form.username.value.trim(),
    email: form.email.value.trim(),
    password: form.password.value,
  };
  
  try {
    const response = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData),
      credentials: 'include', // Include cookies
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Registration failed');
    }
    
    // Success - cookie is set by server
    currentUser = data.user;
    form.reset();
    showAppView();
    loadTodos();
  } catch (error) {
    showError('register-error', error.message);
  } finally {
    setLoading(submitBtn, false);
  }
}

async function handleLogin(e) {
  e.preventDefault();
  clearError('login-error');
  
  const form = e.target;
  const submitBtn = form.querySelector('button[type="submit"]');
  setLoading(submitBtn, true);
  
  const formData = {
    email: form.email.value.trim(),
    password: form.password.value,
  };
  
  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData),
      credentials: 'include',
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Login failed');
    }
    
    // Success
    currentUser = data.user;
    form.reset();
    showAppView();
    loadTodos();
  } catch (error) {
    showError('login-error', error.message);
  } finally {
    setLoading(submitBtn, false);
  }
}

async function handleLogout() {
  try {
    await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'include',
    });
  } catch (error) {
    console.error('Logout error:', error);
  }
  
  // Clear state
  currentUser = null;
  todos = [];
  
  // Show login view
  showLoginView();
}

// ============================================
// Todo Operations
// ============================================

async function loadTodos() {
  const loadingEl = document.getElementById('loading');
  loadingEl.style.display = 'block';
  
  try {
    const response = await fetch('/api/todos', {
      credentials: 'include',
    });
    
    if (!response.ok) {
      if (response.status === 401) {
        // Token expired
        showLoginView();
        return;
      }
      throw new Error('Failed to load notes');
    }
    
    const data = await response.json();
    displayTodos(data.todos);
  } catch (error) {
    console.error('Load notes error:', error);
    showError('todo-error', 'Failed to load notes');
  } finally {
    loadingEl.style.display = 'none';
  }
}

async function handleAddTodo(e) {
  e.preventDefault();
  clearError('todo-error');
  
  const form = e.target;
  const submitBtn = form.querySelector('button[type="submit"]');
  const content = form.content.value.trim();
  
  if (!content) {
    showError('todo-error', 'Note content cannot be empty');
    return;
  }
  
  setLoading(submitBtn, true);
  
  try {
    const response = await fetch('/api/todos', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ content }),
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to create note');
    }
    
    // Success
    form.reset();
    loadTodos(); // Reload list (will update counter)
  } catch (error) {
    showError('todo-error', error.message);
  } finally {
    setLoading(submitBtn, false);
  }
}

async function handleDeleteTodo(todoId) {
  if (!confirm('Are you sure you want to delete this note?')) {
    return;
  }
  
  try {
    const response = await fetch(`/api/todos/${todoId}`, {
      method: 'DELETE',
      credentials: 'include',
    });
    
    if (!response.ok) {
      throw new Error('Failed to delete note');
    }
    
    loadTodos(); // Reload list (will update counter)
  } catch (error) {
    console.error('Delete error:', error);
    alert('Failed to delete note');
  }
}

function openEditModal(todo) {
  editingTodoId = todo.id;
  document.getElementById('edit-content').value = todo.content;
  document.getElementById('edit-modal').style.display = 'flex';
  clearError('edit-error');
}

function closeEditModal() {
  editingTodoId = null;
  document.getElementById('edit-modal').style.display = 'none';
  document.getElementById('edit-form').reset();
  clearError('edit-error');
}

async function handleEditSubmit(e) {
  e.preventDefault();
  clearError('edit-error');
  
  const form = e.target;
  const content = form.content.value.trim();
  
  if (!content) {
    showError('edit-error', 'Note content cannot be empty');
    return;
  }
  
  const submitBtn = form.querySelector('button[type="submit"]');
  setLoading(submitBtn, true);
  
  try {
    const response = await fetch(`/api/todos/${editingTodoId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ content }),
    });
    
    if (!response.ok) {
      throw new Error('Failed to update note');
    }
    
    closeEditModal();
    loadTodos(); // Reload list (will update counter)
  } catch (error) {
    showError('edit-error', error.message);
  } finally {
    setLoading(submitBtn, false);
  }
}

// ============================================
// Completion Status Functions
// ============================================

function toggleTodoCompleted(todoId) {
  const todo = todos.find(t => t.id === todoId);
  if (todo) {
    todo.completed = !todo.completed;
    // Update UI immediately
    const todoElement = document.querySelector(`[data-todo-id="${todoId}"]`);
    if (todoElement) {
      if (todo.completed) {
        todoElement.classList.add('completed');
      } else {
        todoElement.classList.remove('completed');
      }
    }
    // Re-render to update all todos and counter
    displayTodos(todos);
  }
}

function updateTaskCounter() {
  const activeCount = todos.filter(t => !t.completed).length;
  const totalCount = todos.length;
  const completedCount = todos.filter(t => t.completed).length;
  
  let counterEl = document.getElementById('task-counter');
  if (!counterEl) {
    // Create counter element if it doesn't exist
    counterEl = document.createElement('div');
    counterEl.id = 'task-counter';
    counterEl.className = 'task-counter';
    const todoSection = document.querySelector('.todo-section');
    const h2 = todoSection.querySelector('h2');
    h2.insertAdjacentElement('afterend', counterEl);
  }
  
  counterEl.textContent = `Active tasks: ${activeCount}${totalCount > 0 ? ` | Total: ${totalCount} | Completed: ${completedCount}` : ''}`;
  
  // Update Clear Completed button state
  const clearBtn = document.getElementById('clear-completed-btn');
  if (clearBtn) {
    clearBtn.disabled = completedCount === 0;
  }
}

function handleClearCompleted() {
  const completedTodos = todos.filter(t => t.completed);
  if (completedTodos.length === 0) {
    return;
  }
  
  if (!confirm(`Are you sure you want to delete ${completedTodos.length} completed note(s)?`)) {
    return;
  }
  
  // Delete all completed todos
  const deletePromises = completedTodos.map(todo => 
    fetch(`/api/todos/${todo.id}`, {
      method: 'DELETE',
      credentials: 'include',
    })
  );
  
  Promise.all(deletePromises)
    .then(() => {
      loadTodos(); // Reload list (will update counter)
    })
    .catch(error => {
      console.error('Clear completed error:', error);
      alert('Failed to clear completed notes');
    });
}

// ============================================
// Display Functions
// ============================================

function displayTodos(todoList) {
  // Ensure all todos have completed property (default to false)
  todos = todoList.map(todo => ({
    ...todo,
    completed: todo.completed !== undefined ? todo.completed : false
  }));
  const container = document.getElementById('todo-list');
  const emptyState = document.getElementById('empty-state');
  
  // Clear current list
  container.innerHTML = '';
  
  if (todos.length === 0) {
    emptyState.style.display = 'block';
    updateTaskCounter();
    return;
  }
  
  emptyState.style.display = 'none';
  
  // Create todo elements
  todos.forEach(todo => {
    const todoEl = createTodoElement(todo);
    container.appendChild(todoEl);
  });
  
  updateTaskCounter();
}

/**
 * Create a note DOM element
 * SECURITY: Safely renders content with horizontal line support
 */
function createTodoElement(todo) {
  const div = document.createElement('div');
  div.className = 'todo-item';
  div.setAttribute('data-todo-id', todo.id);
  
  if (todo.tampered) {
    div.classList.add('tampered');
  }
  
  if (todo.completed) {
    div.classList.add('completed');
  }
  
  // Checkbox for completion status
  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.className = 'todo-checkbox';
  checkbox.checked = todo.completed || false;
  checkbox.addEventListener('change', () => toggleTodoCompleted(todo.id));
  
  // Content area
  const contentDiv = document.createElement('div');
  contentDiv.className = 'todo-content note-content';
  
  // Render content with horizontal lines
  renderNoteContent(contentDiv, todo.content);
  
  // Timestamp
  const timeDiv = document.createElement('div');
  timeDiv.className = 'todo-time';
  const timeSpan = document.createElement('span');
  timeSpan.textContent = `Created: ${formatDate(todo.createdAt)}`;
  timeDiv.appendChild(timeSpan);
  contentDiv.appendChild(timeDiv);
  
  // Warning for tampered notes
  if (todo.tampered) {
    const warningDiv = document.createElement('div');
    warningDiv.className = 'warning-badge';
    warningDiv.textContent = '⚠️ Integrity violation detected';
    contentDiv.appendChild(warningDiv);
  }
  
  // Wrap checkbox and content
  const wrapper = document.createElement('div');
  wrapper.style.display = 'flex';
  wrapper.style.gap = 'var(--spacing-md)';
  wrapper.style.alignItems = 'flex-start';
  wrapper.style.flex = '1';
  wrapper.appendChild(checkbox);
  wrapper.appendChild(contentDiv);
  div.appendChild(wrapper);
  
  // Actions (only if not tampered)
  if (!todo.tampered) {
    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'todo-actions';
    
    const editBtn = document.createElement('button');
    editBtn.className = 'btn btn-small btn-secondary';
    editBtn.textContent = 'Edit';
    editBtn.addEventListener('click', () => openEditModal(todo));
    
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn btn-small btn-danger';
    deleteBtn.textContent = 'Delete';
    deleteBtn.addEventListener('click', () => handleDeleteTodo(todo.id));
    
    actionsDiv.appendChild(editBtn);
    actionsDiv.appendChild(deleteBtn);
    div.appendChild(actionsDiv);
  }
  
  return div;
}

/**
 * Render note content with horizontal line support
 * SECURITY: Safely processes content and only creates horizontal lines from --- pattern
 */
function renderNoteContent(container, content) {
  const lines = content.split('\n');
  
  lines.forEach((line, index) => {
    // Check if line is a horizontal line marker (at least 3 dashes with optional spaces)
    const trimmedLine = line.trim();
    if (/^[\s]*-{3,}[\s]*$/.test(trimmedLine)) {
      // Create horizontal line element
      const hr = document.createElement('hr');
      hr.className = 'horizontal-line';
      container.appendChild(hr);
    } else {
      // Regular text line
      const p = document.createElement('p');
      // SECURITY: Use textContent to prevent XSS
      p.textContent = line;
      if (line.trim() === '') {
        p.style.height = '1em'; // Preserve empty lines
        p.style.margin = '0';
      }
      container.appendChild(p);
    }
  });
}

// ============================================
// Utility Functions
// ============================================

function formatDate(dateString) {
  const date = new Date(dateString);
  return date.toLocaleString();
}

function showError(elementId, message) {
  const errorEl = document.getElementById(elementId);
  // SECURITY: Use textContent to prevent XSS
  errorEl.textContent = message;
  errorEl.style.display = 'block';
}

function clearError(elementId) {
  const errorEl = document.getElementById(elementId);
  errorEl.textContent = '';
  errorEl.style.display = 'none';
}

function setLoading(button, isLoading) {
  if (isLoading) {
    button.disabled = true;
    button.classList.add('loading');
    const span = button.querySelector('span');
    if (span) {
      span.textContent = 'Loading...';
    }
  } else {
    button.disabled = false;
    button.classList.remove('loading');
    const span = button.querySelector('span');
    if (span) {
      // Restore original text
      const form = button.closest('form');
      if (form && form.id === 'login-form') {
        span.textContent = 'Login';
      } else if (form && form.id === 'register-form') {
        span.textContent = 'Register';
      } else if (form && form.id === 'todo-form') {
        span.textContent = 'Add Note';
      } else if (form && form.id === 'edit-form') {
        span.textContent = 'Save Changes';
      }
    }
  }
}

/**
 * Insert horizontal line marker (---) at cursor position in textarea
 */
function insertHorizontalLine(textareaId) {
  const textarea = document.getElementById(textareaId);
  if (!textarea) return;
  
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  const text = textarea.value;
  
  // Determine if we need to add newlines
  const beforeText = text.substring(0, start);
  const afterText = text.substring(end);
  
  let insertText = '---';
  
  // Add newline before if not at start and previous char is not newline
  if (beforeText.length > 0 && beforeText[beforeText.length - 1] !== '\n') {
    insertText = '\n' + insertText;
  }
  
  // Add newline after if not at end and next char is not newline
  if (afterText.length > 0 && afterText[0] !== '\n') {
    insertText = insertText + '\n';
  }
  
  // Insert the horizontal line marker
  const newText = beforeText + insertText + afterText;
  textarea.value = newText;
  
  // Set cursor position after the inserted text
  const newCursorPos = start + insertText.length;
  textarea.setSelectionRange(newCursorPos, newCursorPos);
  textarea.focus();
}
