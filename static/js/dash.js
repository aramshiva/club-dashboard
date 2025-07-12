// Global variables
let clubId = '';
let joinCode = '';


// Initialize the application when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing club dashboard...');

    // Get the club ID and join code from data attributes
    const dashboardElement = document.querySelector('.club-dashboard');
    if (dashboardElement) {
        clubId = dashboardElement.dataset.clubId || '';
        joinCode = dashboardElement.dataset.joinCode || '';
        console.log('Retrieved Club ID:', clubId);
        console.log('Retrieved Join Code:', joinCode);
    }

    // Removed welcome toast since notifications are working

    // Initialize navigation
    initNavigation();

    // Load initial data if club ID exists
    if (clubId) {
        loadInitialData();
    }

    // Setup settings form handler
    setupSettingsForm();
});

// Setup settings form handler
function setupSettingsForm() {
    const settingsForm = document.getElementById('clubSettingsForm');
    if (settingsForm) {
        settingsForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const clubName = document.getElementById('clubName').value;
            const clubDescription = document.getElementById('clubDescription').value;
            const clubLocation = document.getElementById('clubLocation').value;

            if (!clubId) {
                showToast('error', 'Cannot update settings: Club ID is missing.', 'Error');
                return;
            }

            updateClubSettings(clubName, clubDescription, clubLocation);
        });
    }
}

// Utility function to safely escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Utility function to create DOM elements safely
function createElement(tag, className = '', textContent = '') {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (textContent) element.textContent = textContent;
    return element;
}

// Initialize navigation - only target sidebar nav links
function initNavigation() {
    console.log('Setting up sidebar navigation...');

    // IMPORTANT: Only target the sidebar navigation links, not the top navbar
    const sidebarNavLinks = document.querySelectorAll('.dashboard-sidebar .nav-link');
    console.log('Found sidebar nav links:', sidebarNavLinks.length);

    sidebarNavLinks.forEach(link => {
        // Remove existing listeners by cloning and replacing
        const newLink = link.cloneNode(true);
        link.parentNode.replaceChild(newLink, link);

        // Add direct onclick property (most reliable method)
        newLink.onclick = function(e) {
            // Special handling for shop links and project submission - let them navigate normally
            if (this.classList.contains('shop-link') || this.classList.contains('project-link')) {
                return true; // Allow normal navigation
            }
            
            e.preventDefault();
            console.log('Sidebar nav link clicked!'); 
            const section = this.getAttribute('data-section');
            console.log('Section:', section);
            if (section) {
                openTab(section);
                return false; // Prevent default and stop propagation
            }
        };
    });

    // Leave the main navbar links alone - they should navigate to URLs

    // Open default tab or the one from URL hash
    const hash = window.location.hash.substring(1);
    if (hash) {
        openTab(hash);
    } else {
        openTab('dashboard');
    }
}

// Load initial data for the dashboard
function loadInitialData() {
    if (!clubId) return;

    loadPosts();
    loadAssignments();
    loadMeetings();
}

// Note: showToast function is provided globally in base.html
// We don't need to redefine it here

function openTab(sectionName) {
    if (!sectionName) return;

    console.log('Opening tab:', sectionName);

    // Get all sections and deactivate them
    const allSections = document.querySelectorAll('.club-section');
    allSections.forEach(section => {
        section.classList.remove('active');
    });

    // Activate the selected section
    const targetSection = document.getElementById(sectionName);
    if (targetSection) {
        targetSection.classList.add('active');
    } else {
        console.warn('Section not found:', sectionName);
        return;
    }

    // Update navigation links
    const allNavLinks = document.querySelectorAll('.nav-link');
    allNavLinks.forEach(link => {
        link.classList.remove('active');
    });

    const activeNavLink = document.querySelector(`.nav-link[data-section="${sectionName}"]`);
    if (activeNavLink) {
        activeNavLink.classList.add('active');
    }

    // Load section data
    loadSectionData(sectionName);
}


function loadSectionData(section) {
    switch(section) {
        case 'stream':
            loadPosts();
            break;
        case 'assignments':
            loadAssignments();
            break;
        case 'schedule':
            loadMeetings();
            break;
        case 'resources':
            loadResources();
            break;
    }
}

function deletePost(postId, content) {
    const preview = content.length > 50 ? content.substring(0, 50) + '...' : content;
    showConfirmModal(
        `Delete post?`,
        `"${preview}"`,
        () => {
            fetch(`/api/clubs/${clubId}/posts/${postId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.message || data.success) {
                    loadPosts();
                    showToast('success', 'Post deleted successfully', 'Post Deleted');
                } else {
                    showToast('error', data.error || 'Failed to delete post', 'Error');
                }
            })
            .catch(error => {
                showToast('error', 'Error deleting post', 'Error');
            });
        }
    );
}

function deleteAssignment(assignmentId, title) {
    showConfirmModal(
        `Delete "${title}"?`,
        'This action cannot be undone.',
        () => {
            fetch(`/api/clubs/${clubId}/assignments/${assignmentId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.message || data.success) {
                    loadAssignments();
                    showToast('success', 'Assignment deleted successfully', 'Assignment Deleted');
                } else {
                    showToast('error', data.error || 'Failed to delete assignment', 'Error');
                }
            })
            .catch(error => {
                showToast('error', 'Error deleting assignment', 'Error');
            });
        }
    );
}

function showQRModal() {
    if (!joinCode) {
        showToast('error', 'Join code is not available to generate QR code.', 'Error');
        console.error('Join code is undefined, cannot generate QR code.');
        return;
    }
    const joinUrl = `${window.location.origin}/join-club?code=${joinCode}`;
    const joinUrlInput = document.getElementById('joinUrl');
    if (joinUrlInput) {
        joinUrlInput.value = joinUrl;
    } else {
        console.warn('joinUrl input element not found in QR modal.');
    }

    const qrContainer = document.getElementById('qrcode');
    if (!qrContainer) {
        console.error('QR code container not found');
        return;
    }

    qrContainer.innerHTML = '';

    const canvas = document.createElement('canvas');
    qrContainer.appendChild(canvas);

    QRCode.toCanvas(canvas, joinUrl, {
        width: 200,
        margin: 2,
        color: {
            dark: '#ec3750',
            light: '#ffffff'
        }
    }, function (error) {
        if (error) {
            console.error('QR Code generation failed:', error);
            qrContainer.innerHTML = '<p style="color: #ef4444;">Failed to generate QR code</p>';
        }
    });

    const modal = document.getElementById('qrModal');
    if (modal) {
        modal.style.display = 'block';
    }
}

function copyJoinUrl() {
    const joinUrl = document.getElementById('joinUrl');
    joinUrl.select();
    document.execCommand('copy');
    showToast('success', 'Join code copied to clipboard!', 'Copied');
}

function generateNewJoinCode() {
    if (!clubId) {
        showToast('error', 'Cannot generate new join code: Club ID is missing.', 'Error');
        console.error('generateNewJoinCode: clubId is missing.');
        return;
    }
    showConfirmModal(
        'Generate a new join code?',
        'The old code will stop working.',
        () => {
            fetch(`/api/clubs/${clubId}/join-code`, {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.join_code) {
                    const joinCodeDisplay = document.querySelector('.join-code-display');
                    if (joinCodeDisplay) {
                        joinCodeDisplay.innerHTML = '';
                        const icon = createElement('i', 'fas fa-key');
                        joinCodeDisplay.appendChild(icon);
                        joinCodeDisplay.appendChild(document.createTextNode(' ' + data.join_code));
                    }
                    // Update the join code in the QR modal input as well
                    const qrCodeInput = document.querySelector('#qrModal input[readonly]');
                    if (qrCodeInput) {
                        qrCodeInput.value = data.join_code;
                    }
                    showToast('success', 'New join code generated!', 'Generated');
                } else {
                    showToast('error', 'Failed to generate new join code', 'Error');
                }
            })
            .catch(error => {
                showToast('error', 'Error generating join code', 'Error');
            });
        }
    );
}

function showConfirmModal(message, details, onConfirm) {
    const confirmMessage = document.getElementById('confirmMessage');
    if (confirmMessage) {
        confirmMessage.innerHTML = '';
        confirmMessage.appendChild(document.createTextNode(message));
        if (details) {
            confirmMessage.appendChild(createElement('br'));
            const small = createElement('small', '', details);
            confirmMessage.appendChild(small);
        }
    }
    document.getElementById('confirmModal').style.display = 'block';

    document.getElementById('confirmButton').onclick = () => {
        document.getElementById('confirmModal').style.display = 'none';
        onConfirm();
    };
}

function loadPosts() {
    if (!clubId) {
        console.warn('loadPosts: clubId is missing. Skipping fetch.');
        const postsList = document.getElementById('postsList');
        if (postsList) postsList.textContent = 'Error: Club information is unavailable to load posts.';
        return;
    }
    fetch(`/api/clubs/${clubId}/posts`)
        .then(response => response.json())
        .then(data => {
            const postsList = document.getElementById('postsList');
            postsList.innerHTML = '';

            if (data.posts && data.posts.length > 0) {
                data.posts.forEach(post => {
                    const postCard = createElement('div', 'post-card');

                    const postHeader = createElement('div', 'post-header');
                    const postAvatar = createElement('div', 'post-avatar', post.user.username[0].toUpperCase());
                    const postInfo = createElement('div', 'post-info');
                    const postUsername = createElement('h4', '', post.user.username);
                    const postDate = createElement('div', 'post-date', new Date(post.created_at).toLocaleDateString());

                    postInfo.appendChild(postUsername);
                    postInfo.appendChild(postDate);
                    postHeader.appendChild(postAvatar);
                    postHeader.appendChild(postInfo);

                    // Add delete button for club leaders
                    if (window.clubData && window.clubData.isLeader) {
                        const deleteBtn = createElement('button', 'btn-icon delete-btn');
                        deleteBtn.setAttribute('onclick', `deletePost(${post.id}, '${post.content.replace(/'/g, "\\'")}')`)
                        deleteBtn.setAttribute('title', 'Delete Post');
                        deleteBtn.innerHTML = '<i class="fas fa-trash"></i>';
                        postHeader.appendChild(deleteBtn);
                    }

                    const postContent = createElement('div', 'post-content');
                    const postText = createElement('p', '', post.content);
                    postContent.appendChild(postText);

                    postCard.appendChild(postHeader);
                    postCard.appendChild(postContent);
                    postsList.appendChild(postCard);
                });
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-stream');
                const title = createElement('h3', '', 'No posts yet');
                const description = createElement('p', '', 'Be the first to share something with your club!');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                postsList.appendChild(emptyState);
            }
        })
        .catch(error => {
            showToast('error', 'Failed to load posts', 'Error');
        });
}

function createPost() {
    if (!clubId) {
        showToast('error', 'Cannot create post: Club ID is missing.', 'Error');
        console.error('createPost: clubId is missing.');
        return;
    }
    const content = document.getElementById('postContent').value;
    if (!content.trim()) {
        showToast('error', 'Please enter some content', 'Validation Error');
        return;
    }

    fetch(`/api/clubs/${clubId}/posts`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ content })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            document.getElementById('postContent').value = '';
            loadPosts();
            showToast('success', 'Post created successfully', 'Post Created');
        } else {
            showToast('error', data.error || 'Failed to create post', 'Error');
        }
    })
    .catch(error => {
        showToast('error', 'Error creating post', 'Error');
    });
}

function openCreateAssignmentModal() {
    const modal = document.getElementById('createAssignmentModal');
    if (modal) modal.style.display = 'block';
}

function createAssignment() {
    if (!clubId) {
        showToast('error', 'Cannot create assignment: Club ID is missing.', 'Error');
        console.error('createAssignment: clubId is missing.');
        return;
    }
    const title = document.getElementById('assignmentTitle').value;
    const description = document.getElementById('assignmentDescription').value;
    const dueDate = document.getElementById('assignmentDueDate').value;
    const forAllMembers = document.getElementById('assignmentForAll').checked;

    if (!title || !description) {
        showToast('error', 'Please fill in all required fields', 'Validation Error');
        return;
    }

    fetch(`/api/clubs/${clubId}/assignments`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            title,
            description,
            due_date: dueDate || null,
            for_all_members: forAllMembers
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            document.getElementById('createAssignmentModal').style.display = 'none';
            document.getElementById('createAssignmentForm').reset();
            loadAssignments();
            showToast('success', 'Assignment created successfully', 'Assignment Created');
        } else {
            showToast('error', data.error || 'Failed to create assignment', 'Error');
        }
    })
    .catch(error => {
        showToast('error', 'Error creating assignment', 'Error');
    });
}

function loadAssignments() {
    if (!clubId) {
        console.warn('loadAssignments: clubId is missing. Skipping fetch.');
        const assignmentsList = document.getElementById('assignmentsList');
        if (assignmentsList) assignmentsList.textContent = 'Error: Club information is unavailable to load assignments.';
        return;
    }
    fetch(`/api/clubs/${clubId}/assignments`)
        .then(response => response.json())
        .then(data => {
            const assignmentsList = document.getElementById('assignmentsList');
            const assignmentsCount = document.getElementById('assignmentsCount');

            assignmentsList.innerHTML = '';

            if (data.assignments && data.assignments.length > 0) {
                data.assignments.forEach(assignment => {
                    const card = createElement('div', 'card');
                    card.style.marginBottom = '1rem';

                    const cardHeader = createElement('div', 'card-header');
                    cardHeader.style.cssText = 'display: flex; justify-content: space-between; align-items: flex-start;';

                    const headerDiv = createElement('div');
                    const title = createElement('h3', '', assignment.title);
                    title.style.cssText = 'margin: 0; font-size: 1.125rem; color: #1f2937;';

                    const statusSpan = createElement('span', '', assignment.status);
                    statusSpan.style.cssText = `background: ${assignment.status === 'active' ? '#10b981' : '#6b7280'}; color: white; padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; margin-top: 0.5rem; display: inline-block;`;

                    headerDiv.appendChild(title);
                    headerDiv.appendChild(statusSpan);
                    cardHeader.appendChild(headerDiv);

                    // Add delete button for club leaders
                    if (window.clubData && window.clubData.isLeader) {
                        const deleteBtn = createElement('button', 'btn-icon delete-btn');
                        deleteBtn.setAttribute('onclick', `deleteAssignmentDesktop(${assignment.id}, '${assignment.title.replace(/'/g, "\\'")}')`)
                        deleteBtn.setAttribute('title', 'Delete Assignment');
                        deleteBtn.innerHTML = '<i class="fas fa-trash"></i>';
                        cardHeader.appendChild(deleteBtn);
                    }

                    const cardBody = createElement('div', 'card-body');
                    const description = createElement('p', '', assignment.description);
                    description.style.cssText = 'margin-bottom: 1rem; color: #6b7280;';
                    cardBody.appendChild(description);

                    const infoDiv = createElement('div');
                    infoDiv.style.cssText = 'display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.875rem; color: #6b7280;';

                    if (assignment.due_date) {
                        const dueSpan = createElement('span');
                        dueSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                        const dueIcon = createElement('i', 'fas fa-calendar');
                        dueSpan.appendChild(dueIcon);
                        dueSpan.appendChild(document.createTextNode(' Due: ' + new Date(assignment.due_date).toLocaleDateString()));
                        infoDiv.appendChild(dueSpan);
                    }

                    const membersSpan = createElement('span');
                    membersSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                    const membersIcon = createElement('i', 'fas fa-users');
                    membersSpan.appendChild(membersIcon);
                    membersSpan.appendChild(document.createTextNode(' ' + (assignment.for_all_members ? 'All members' : 'Selected members')));
                    infoDiv.appendChild(membersSpan);

                    cardBody.appendChild(infoDiv);
                    card.appendChild(cardHeader);
                    card.appendChild(cardBody);
                    assignmentsList.appendChild(card);
                });

                assignmentsCount.textContent = data.assignments.filter(a => a.status === 'active').length;
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-clipboard-list');
                const title = createElement('h3', '', 'No assignments yet');
                const description = createElement('p', '', 'Create your first assignment to get started!');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                assignmentsList.appendChild(emptyState);

                assignmentsCount.textContent = '0';
            }
        })
        .catch(error => {
            showToast('error', 'Failed to load assignments', 'Error');
        });
}

// Opening the create meeting modal
function openCreateMeetingModal() {
    // Close edit modal if it's open
    if (typeof closeEditMeetingModal === 'function') {
        closeEditMeetingModal();
    }

    // Clear form fields
    const form = document.getElementById('createMeetingForm');
    if (form) form.reset();

    // Show the modal
    const modal = document.getElementById('createMeetingModal');
    if (modal) modal.style.display = 'block';
}

function createMeeting() {
    if (!clubId) {
        showToast('error', 'Cannot create meeting: Club ID is missing.', 'Error');
        console.error('createMeeting: clubId is missing.');
        return;
    }
    const title = document.getElementById('meetingTitle').value;
    const description = document.getElementById('meetingDescription').value;
    const date = document.getElementById('meetingDate').value;
    const startTime = document.getElementById('meetingStartTime').value;
    const endTime = document.getElementById('meetingEndTime').value;
    const location = document.getElementById('meetingLocation').value;
    const link = document.getElementById('meetingLink').value;

    if (!title || !date || !startTime) {
        showToast('error', 'Please fill in all required fields', 'Validation Error');
        return;
    }

    fetch(`/api/clubs/${clubId}/meetings`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            title,
            description,
            meeting_date: date,
            start_time: startTime,
            end_time: endTime,
            location,
            meeting_link: link
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            document.getElementById('createMeetingModal').style.display = 'none';
            document.getElementById('createMeetingForm').reset();
            loadMeetings();
            showToast('success', 'Meeting scheduled successfully', 'Meeting Scheduled');
        } else {
            showToast('error', data.error || 'Failed to schedule meeting', 'Error');
        }
    })
    .catch(error => {
        showToast('error', 'Error scheduling meeting', 'Error');
    });
}

function loadMeetings() {
    if (!clubId) {
        console.warn('loadMeetings: clubId is missing. Skipping fetch.');
        const meetingsList = document.getElementById('meetingsList');
        if (meetingsList) meetingsList.textContent = 'Error: Club information is unavailable to load meetings.';
        return;
    }
    fetch(`/api/clubs/${clubId}/meetings`)
        .then(response => response.json())
        .then(data => {
            const meetingsList = document.getElementById('meetingsList');
            const meetingsCount = document.getElementById('meetingsCount');

            meetingsList.innerHTML = '';

            if (data.meetings && data.meetings.length > 0) {
                data.meetings.forEach(meeting => {
                    const card = createElement('div', 'card');
                    card.style.marginBottom = '1rem';
                    card.id = `meeting-${meeting.id}`;

                    const cardHeader = createElement('div', 'card-header');
                    cardHeader.style.cssText = 'display: flex; justify-content: space-between; align-items: flex-start;';

                    const headerDiv = createElement('div');
                    const title = createElement('h3', '', meeting.title);
                    title.style.cssText = 'margin: 0; font-size: 1.125rem; color: #1f2937;';
                    headerDiv.appendChild(title);
                    cardHeader.appendChild(headerDiv);

                    // Add delete button for club leaders
                    if (window.clubData && window.clubData.isLeader) {
                        const deleteBtn = createElement('button', 'btn-icon delete-btn');
                        deleteBtn.setAttribute('onclick', `deleteMeetingDesktop(${meeting.id}, '${meeting.title.replace(/'/g, "\\'")}')`)
                        deleteBtn.setAttribute('title', 'Delete Meeting');
                        deleteBtn.innerHTML = '<i class="fas fa-trash"></i>';
                        cardHeader.appendChild(deleteBtn);
                    }

                    const cardBody = createElement('div', 'card-body');

                    if (meeting.description) {
                        const description = createElement('p', '', meeting.description);
                        description.style.cssText = 'margin-bottom: 1rem; color: #6b7280;';
                        cardBody.appendChild(description);
                    }

                    const infoDiv = createElement('div');
                    infoDiv.style.cssText = 'display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.875rem; color: #6b7280;';

                    const dateSpan = createElement('span');
                    dateSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                    const dateIcon = createElement('i', 'fas fa-calendar');
                    dateSpan.appendChild(dateIcon);
                    dateSpan.appendChild(document.createTextNode(' ' + new Date(meeting.meeting_date).toLocaleDateString()));
                    infoDiv.appendChild(dateSpan);

                    const timeSpan = createElement('span');
                    timeSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                    const timeIcon = createElement('i', 'fas fa-clock');
                    timeSpan.appendChild(timeIcon);
                    const timeText = meeting.start_time + (meeting.end_time ? ` - ${meeting.end_time}` : '');
                    timeSpan.appendChild(document.createTextNode(' ' + timeText));
                    infoDiv.appendChild(timeSpan);

                    if (meeting.location) {
                        const locationSpan = createElement('span');
                        locationSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                        const locationIcon = createElement('i', 'fas fa-map-marker-alt');
                        locationSpan.appendChild(locationIcon);
                        locationSpan.appendChild(document.createTextNode(' ' + meeting.location));
                        infoDiv.appendChild(locationSpan);
                    }

                    if (meeting.meeting_link) {
                        const linkSpan = createElement('span');
                        linkSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                        const linkIcon = createElement('i', 'fas fa-link');
                        linkSpan.appendChild(linkIcon);
                        linkSpan.appendChild(document.createTextNode(' '));

                        const link = createElement('a');
                        link.href = meeting.meeting_link;
                        link.target = '_blank';
                        link.style.color = '#ec3750';
                        link.textContent = 'Visit Resource';
                        linkSpan.appendChild(link);
                        infoDiv.appendChild(linkSpan);
                    }

                    cardBody.appendChild(infoDiv);
                    card.appendChild(cardHeader);
                    card.appendChild(cardBody);
                    meetingsList.appendChild(card);
                });

                const thisMonth = new Date().getMonth();
                const thisYear = new Date().getFullYear();
                const thisMonthMeetings = data.meetings.filter(m => {
                    const meetingDate = new Date(m.meeting_date);
                    return meetingDate.getMonth() === thisMonth && meetingDate.getFullYear() === thisYear;
                });
                meetingsCount.textContent = thisMonthMeetings.length;
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-calendar-times');
                const title = createElement('h3', '', 'No meetings scheduled');
                const description = createElement('p', '', 'Schedule your first club meeting to get started!');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                meetingsList.appendChild(emptyState);

                meetingsCount.textContent = '0';
            }
        })
        .catch(error => {
            showToast('error', 'Failed to load meetings', 'Error');
        });
}

function editMeeting(id, title, description, date, startTime, endTime, location, link) {
    // Populate edit form
    document.getElementById('meetingTitle').value = title;
    document.getElementById('meetingDescription').value = description;
    document.getElementById('meetingDate').value = date;
    document.getElementById('meetingStartTime').value = startTime;
    document.getElementById('meetingEndTime').value = endTime;
    document.getElementById('meetingLocation').value = location;
    document.getElementById('meetingLink').value = link;

    // Change form action to update
    document.getElementById('createMeetingModal').setAttribute('data-edit-id', id);
    document.querySelector('#createMeetingModal .modal-header h3').textContent = 'Edit Meeting';
    const submitBtn = document.querySelector('#createMeetingModal .btn-primary');
    submitBtn.textContent = '';
    const icon = createElement('i', 'fas fa-save');
    submitBtn.appendChild(icon);
    submitBtn.appendChild(document.createTextNode(' Update Meeting'));
    submitBtn.setAttribute('onclick', 'updateMeeting()');

    const modal = document.getElementById('createMeetingModal');
    if (modal) modal.style.display = 'block';
}

function updateMeeting() {
    const id = document.getElementById('createMeetingModal').getAttribute('data-edit-id');
    const title = document.getElementById('meetingTitle').value;
    const description = document.getElementById('meetingDescription').value;
    const date = document.getElementById('meetingDate').value;
    const startTime = document.getElementById('meetingStartTime').value;
    const endTime = document.getElementById('meetingEndTime').value;
    const location = document.getElementById('meetingLocation').value;
    const link = document.getElementById('meetingLink').value;

    if (!title || !date || !startTime) {
        showToast('error', 'Please fill in all required fields', 'Validation Error');
        return;
    }

    fetch(`/api/clubs/${clubId}/meetings/${id}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            title,
            description,
            meeting_date: date,
            start_time: startTime,
            end_time: endTime,
            location,
            meeting_link: link
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            closeEditMeetingModal();
            loadMeetings();
            showToast('success', 'Meeting updated successfully', 'Meeting Updated');
        } else {
            showToast('error', data.error || 'Failed to update meeting', 'Error');
        }
    })
    .catch(error => {
        showToast('error', 'Error updating meeting', 'Error');
    });
}

function deleteMeeting(id, title) {
    showConfirmModal(
        `Delete "${title}"?`,
        'This action cannot be undone.',
        () => {
            fetch(`/api/clubs/${clubId}/meetings/${id}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.message) {
                    loadMeetings();
                    showToast('success', 'Meeting deleted successfully', 'Meeting Deleted');
                } else {
                    showToast('error', data.error || 'Failed to delete meeting', 'Error');
                }
            })
            .catch(error => {
                showToast('error', 'Error deleting meeting', 'Error');
            });
        }
    );
}

function closeEditMeetingModal() {
    const modal = document.getElementById('createMeetingModal');
    if (modal){
        modal.style.display = 'none';
        modal.removeAttribute('data-edit-id');
    }
    document.querySelector('#createMeetingModal .modal-header h3').textContent = 'Schedule Meeting';
    const submitBtn = document.querySelector('#createMeetingModal .btn-primary');
    submitBtn.textContent = '';
    const icon = createElement('i', 'fas fa-calendar-plus');
    submitBtn.appendChild(icon);
    submitBtn.appendChild(document.createTextNode(' Schedule Meeting'));
    submitBtn.setAttribute('onclick', 'createMeeting()');
    document.getElementById('createMeetingForm').reset();
}

// This comment is kept to maintain line numbers, but the duplicate function has been removed

function loadProjects() {
    if (!clubId) {
        console.warn('loadProjects: clubId is missing. Skipping fetch.');
        const projectsList = document.getElementById('projects-list'); // Ensure this ID matches your HTML
        if (projectsList) projectsList.textContent = 'Error: Club information is unavailable to load projects.';
        return;
    }
    fetch(`/api/clubs/${clubId}/projects`)
        .then(response => response.json())
        .then(data => {
            const projectsList = document.getElementById('projectsList');
            const projectsCount = document.getElementById('projectsCount');

            projectsList.innerHTML = '';

            if (data.projects && data.projects.length > 0) {
                data.projects.forEach(project => {
                    const card = createElement('div', 'card');
                    card.style.marginBottom = '1rem';

                    const cardHeader = createElement('div', 'card-header');
                    cardHeader.style.cssText = 'display: flex; justify-content: space-between; align-items: flex-start;';

                    const headerDiv = createElement('div');
                    const title = createElement('h3', '', project.name);
                    title.style.cssText = 'margin: 0; font-size: 1.125rem; color: #1f2937;';
                    headerDiv.appendChild(title);

                    if (project.featured) {
                        const featuredSpan = createElement('span', '', 'Featured');
                        featuredSpan.style.cssText = 'background: #f59e0b; color: white; padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; margin-top: 0.5rem; display: inline-block;';
                        headerDiv.appendChild(featuredSpan);
                    }

                    cardHeader.appendChild(headerDiv);

                    const cardBody = createElement('div', 'card-body');
                    const description = createElement('p', '', project.description || 'No description available');
                    description.style.cssText = 'margin-bottom: 1rem; color: #6b7280;';
                    cardBody.appendChild(description);

                    const infoDiv = createElement('div');
                    infoDiv.style.cssText = 'display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.875rem; color: #6b7280;';

                    const ownerSpan = createElement('span');
                    ownerSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                    const ownerIcon = createElement('i', 'fas fa-user');
                    ownerSpan.appendChild(ownerIcon);
                    ownerSpan.appendChild(document.createTextNode(' ' + project.owner.username));
                    infoDiv.appendChild(ownerSpan);

                    const dateSpan = createElement('span');
                    dateSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                    const dateIcon = createElement('i', 'fas fa-calendar');
                    dateSpan.appendChild(dateIcon);
                    dateSpan.appendChild(document.createTextNode(' ' + new Date(project.updated_at).toLocaleDateString()));
                    infoDiv.appendChild(dateSpan);

                    cardBody.appendChild(infoDiv);
                    card.appendChild(cardHeader);
                    card.appendChild(cardBody);
                    projectsList.appendChild(card);
                });

                projectsCount.textContent = data.projects.length;
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-code');
                const title = createElement('h3', '', 'No projects yet');
                const description = createElement('p', '', 'Members can start creating projects to showcase here!');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                projectsList.appendChild(emptyState);

                projectsCount.textContent = '0';
            }
        })
        .catch(error => {
            showToast('error', 'Failed to load projects', 'Error');
        });
}

// Opening the add resource modal
function openAddResourceModal() {
    // Close edit modal if it's open
    if (typeof closeEditResourceModal === 'function') {
        closeEditResourceModal();
    }

    // Clear form fields
    const form = document.getElementById('addResourceForm');
    if (form) form.reset();

    // Show the modal
    const modal = document.getElementById('addResourceModal');
    if (modal) modal.style.display = 'block';
}

function addResource() {
    if (!clubId) {
        showToast('error', 'Cannot add resource: Club ID is missing.', 'Error');
        console.error('addResource: clubId is missing.');
        return;
    }
    const title = document.getElementById('resourceTitle').value;
    const url = document.getElementById('resourceUrl').value;
    const description = document.getElementById('resourceDescription').value;
    const icon = document.getElementById('resourceIcon').value;

    if (!title || !url) {
        showToast('error', 'Please fill in title and URL', 'Validation Error');
        return;
    }

    fetch(`/api/clubs/${clubId}/resources`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            title,
            url,
            description,
            icon
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            document.getElementById('addResourceModal').style.display = 'none';
            document.getElementById('addResourceForm').reset();
            loadResources();
            showToast('success', 'Resource added successfully', 'Resource Added');
        } else {
            showToast('error', data.error || 'Failed to add resource', 'Error');
        }
    })
    .catch(error => {
        showToast('error', 'Error adding resource', 'Error');
    });
}

function loadResources() {
    if (!clubId) {
        console.warn('loadResources: clubId is missing. Skipping fetch.');
        const resourcesList = document.getElementById('resourcesList');
        if (resourcesList) resourcesList.textContent = 'Error: Club information is unavailable to load resources.';
        return;
    }
    fetch(`/api/clubs/${clubId}/resources`)
        .then(response => response.json())
        .then(data => {
            const resourcesList = document.getElementById('resourcesList');
            resourcesList.innerHTML = '';

            if (data.resources && data.resources.length > 0) {
                data.resources.forEach(resource => {
                    const card = createElement('div', 'card');
                    card.style.marginBottom = '1rem';
                    card.id = `resource-${resource.id}`;

                    const cardHeader = createElement('div', 'card-header');
                    cardHeader.style.cssText = 'display: flex; justify-content: space-between; align-items: flex-start;';

                    const headerDiv = createElement('div');
                    const title = createElement('h3');
                    title.style.cssText = 'margin: 0; font-size: 1.125rem; color: #1f2937;';
                    const icon = createElement('i', `fas fa-${resource.icon}`);
                    title.appendChild(icon);
                    title.appendChild(document.createTextNode(' ' + resource.title));
                    headerDiv.appendChild(title);
                    cardHeader.appendChild(headerDiv);

                    // Add delete button for club leaders
                    if (window.clubData && window.clubData.isLeader) {
                        const deleteBtn = createElement('button', 'btn-icon delete-btn');
                        deleteBtn.setAttribute('onclick', `deleteResourceDesktop(${resource.id}, '${resource.title.replace(/'/g, "\\'")}')`)
                        deleteBtn.setAttribute('title', 'Delete Resource');
                        deleteBtn.innerHTML = '<i class="fas fa-trash"></i>';
                        cardHeader.appendChild(deleteBtn);
                    }

                    const cardBody = createElement('div', 'card-body');

                    if (resource.description) {
                        const description = createElement('p', '', resource.description);
                        description.style.cssText = 'margin-bottom: 1rem; color: #6b7280;';
                        cardBody.appendChild(description);
                    }

                    const infoDiv = createElement('div');
                    infoDiv.style.cssText = 'display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.875rem; color: #6b7280;';

                    const linkSpan = createElement('span');
                    linkSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                    const linkIcon = createElement('i', 'fas fa-link');
                    linkSpan.appendChild(linkIcon);
                    linkSpan.appendChild(document.createTextNode(' '));

                    const link = createElement('a');
                    link.href = resource.url;
                    link.target = '_blank';
                    link.style.color = '#ec3750';
                    link.textContent = 'Visit Resource';
                    linkSpan.appendChild(link);
                    infoDiv.appendChild(linkSpan);

                    cardBody.appendChild(infoDiv);
                    card.appendChild(cardHeader);
                    card.appendChild(cardBody);
                    resourcesList.appendChild(card);
                });
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-book');
                const title = createElement('h3', '', 'No resources yet');
                const description = createElement('p', '', 'Add helpful links and learning materials for your club!');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                resourcesList.appendChild(emptyState);
            }
        })
        .catch(error => {
            showToast('error', 'Failed to load resources', 'Error');
        });
}

function editResource(id, title, url, description, icon) {
    // Populate edit form
    document.getElementById('resourceTitle').value = title;
    document.getElementById('resourceUrl').value = url;
    document.getElementById('resourceDescription').value = description;
    document.getElementById('resourceIcon').value = icon;

    // Change form action to update
    document.getElementById('addResourceModal').setAttribute('data-edit-id', id);
    document.querySelector('#addResourceModal .modal-header h3').textContent = 'Edit Resource';
    const submitBtn = document.querySelector('#addResourceModal .btn-primary');
    submitBtn.textContent = '';
    const saveIcon = createElement('i', 'fas fa-save');
    submitBtn.appendChild(saveIcon);
    submitBtn.appendChild(document.createTextNode(' Update Resource'));
    submitBtn.setAttribute('onclick', 'updateResource()');
    const modal = document.getElementById('addResourceModal');
    if (modal) modal.style.display = 'block';
}

function updateResource() {
    const id = document.getElementById('addResourceModal').getAttribute('data-edit-id');
    const title = document.getElementById('resourceTitle').value;
    const url = document.getElementById('resourceUrl').value;
    const description = document.getElementById('resourceDescription').value;
    const icon = document.getElementById('resourceIcon').value;

    if (!title || !url) {
        showToast('error', 'Please fill in title and URL', 'Validation Error');
        return;
    }

    fetch(`/api/clubs/${clubId}/resources/${id}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            title,
            url,
            description,
            icon
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            closeEditResourceModal();
            loadResources();
            showToast('success', 'Resource updated successfully', 'Resource Updated');
        } else {
            showToast('error', data.error || 'Failed to update resource', 'Error');
        }
    })
    .catch(error => {
        showToast('error', 'Error updating resource', 'Error');
    });
}

function deleteResource(id, title) {
    showConfirmModal(
        `Delete "${title}"?`,
        'This action cannot be undone.',
        () => {
            fetch(`/api/clubs/${clubId}/resources/${id}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.message) {
                    loadResources();showToast('success', 'Resource deleted successfully', 'Resource Deleted');
                } else {
                    showToast('error', data.error || 'Failed to delete resource', 'Error');
                }
            })
            .catch(error => {
                showToast('error', 'Error deleting resource', 'Error');
            });
        }
    );
}

function closeEditResourceModal() {
    const modal = document.getElementById('addResourceModal');
    if(modal){
        modal.style.display = 'none';
        modal.removeAttribute('data-edit-id');
    }
    document.querySelector('#addResourceModal .modal-header h3').textContent = 'Add Resource';
    const submitBtn = document.querySelector('#addResourceModal .btn-primary');
    submitBtn.textContent = '';
    const addIcon = createElement('i', 'fas fa-plus');
    submitBtn.appendChild(addIcon);
    submitBtn.appendChild(document.createTextNode(' Add Resource'));
    submitBtn.setAttribute('onclick', 'addResource()');
    document.getElementById('addResourceForm').reset();
}

// Update club settings with email verification workflow
function updateClubSettings(clubName, clubDescription, clubLocation) {
    if (!clubId) {
        showToast('error', 'Cannot update settings: Club ID is missing.', 'Error');
        return;
    }

    // Try to update settings first - backend will handle verification requirement
    fetch(`/api/clubs/${clubId}/settings`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            name: clubName,
            description: clubDescription,
            location: clubLocation
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message || data.success) {
            showToast('success', 'Club settings updated successfully', 'Settings Updated');
            
            // Update the displayed information on the page
            const clubNameDisplay = document.querySelector('.club-name');
            if (clubNameDisplay) clubNameDisplay.textContent = clubName;
            
            const clubDescDisplay = document.querySelector('.club-description');
            if (clubDescDisplay) clubDescDisplay.textContent = clubDescription;
            
            const clubLocDisplay = document.querySelector('.club-location');
            if (clubLocDisplay) clubLocDisplay.textContent = clubLocation;
            
        } else if (data.error && data.error.includes('Email verification required')) {
            // Show verification modal and send code
            showEmailVerificationModal(clubName, clubDescription, clubLocation);
        } else {
            showToast('error', data.error || 'Failed to update settings', 'Error');
        }
    })
    .catch(error => {
        console.error('Error updating settings:', error);
        showToast('error', 'Error updating settings', 'Error');
    });
}

// Show email verification modal
function showEmailVerificationModal(clubName, clubDescription, clubLocation) {
    // Create modal HTML if it doesn't exist
    let modal = document.getElementById('emailVerificationModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'emailVerificationModal';
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3><i class="fas fa-envelope"></i> Email Verification Required</h3>
                    <span class="close" onclick="closeEmailVerificationModal()">&times;</span>
                </div>
                <div class="modal-body">
                    <p>A verification code is being sent to your email address. Please enter the code below to update your club settings.</p>
                    <div class="form-group">
                        <label for="verificationCode">Verification Code:</label>
                        <input type="text" id="verificationCode" class="form-control" placeholder="Enter 5-digit code" maxlength="5">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="closeEmailVerificationModal()">Cancel</button>
                    <button type="button" class="btn btn-primary" onclick="verifyCodeAndUpdateSettings('${clubName}', '${clubDescription}', '${clubLocation}')">
                        <i class="fas fa-check"></i> Verify & Update
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }
    
    // Clear previous code and show modal
    document.getElementById('verificationCode').value = '';
    modal.style.display = 'block';
    
    // Send verification code using the club settings endpoint
    sendVerificationCodeForSettings();
}

// Send verification code for settings update
function sendVerificationCodeForSettings() {
    fetch(`/api/clubs/${clubId}/settings`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            step: 'send_verification'
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message || data.success) {
            showToast('success', 'Verification code sent to your email', 'Code Sent');
        } else {
            showToast('error', data.error || 'Failed to send verification code', 'Error');
        }
    })
    .catch(error => {
        console.error('Error sending verification code:', error);
        showToast('error', 'Error sending verification code', 'Error');
    });
}

// Close email verification modal
function closeEmailVerificationModal() {
    const modal = document.getElementById('emailVerificationModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Verify code and update settings
function verifyCodeAndUpdateSettings(clubName, clubDescription, clubLocation) {
    const verificationCode = document.getElementById('verificationCode').value;
    
    if (!verificationCode || verificationCode.length !== 5) {
        showToast('error', 'Please enter a valid 5-digit verification code', 'Validation Error');
        return;
    }

    // Step 1: Verify the email code first
    fetch(`/api/clubs/${clubId}/settings`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            step: 'verify_email',
            verification_code: verificationCode
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success && data.email_verified) {
            // Step 2: Now update the settings with email_verified flag
            return fetch(`/api/clubs/${clubId}/settings`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: clubName,
                    description: clubDescription,
                    location: clubLocation,
                    email_verified: true
                })
            });
        } else {
            throw new Error(data.error || 'Email verification failed');
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.message || data.success) {
            closeEmailVerificationModal();
            showToast('success', 'Club settings updated successfully', 'Settings Updated');
            
            // Update the displayed information on the page
            const clubNameDisplay = document.querySelector('.club-name');
            if (clubNameDisplay) clubNameDisplay.textContent = clubName;
            
            const clubDescDisplay = document.querySelector('.club-description');
            if (clubDescDisplay) clubDescDisplay.textContent = clubDescription;
            
            const clubLocDisplay = document.querySelector('.club-location');
            if (clubLocDisplay) clubLocDisplay.textContent = clubLocation;
            
        } else {
            showToast('error', data.error || 'Failed to update settings', 'Error');
        }
    })
    .catch(error => {
        console.error('Error in verification process:', error);
        showToast('error', error.message || 'Error updating settings', 'Error');
    });
}
