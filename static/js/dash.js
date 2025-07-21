// Global variables
let clubId = '';
let joinCode = '';


// Initialize the application when DOM is ready
document.addEventListener('DOMContentLoaded', function() {

    // Get the club ID and join code from data attributes
    const dashboardElement = document.querySelector('.club-dashboard');
    if (dashboardElement) {
        clubId = dashboardElement.dataset.clubId || '';
        joinCode = dashboardElement.dataset.joinCode || '';
    }

    // Removed welcome toast since notifications are working

    // Initialize navigation
    initNavigation();

    // Load initial data if club ID exists
    if (clubId) {
        loadInitialData();
        loadQuestData();
    }

    // Setup settings form handler
    setupSettingsForm();
});

// Setup settings form handler
function setupSettingsForm() {
    const settingsForm = document.getElementById('clubSettingsForm');
    if (settingsForm) {
        // Remove any existing listeners to prevent duplicates
        const newForm = settingsForm.cloneNode(true);
        settingsForm.parentNode.replaceChild(newForm, settingsForm);
        
        newForm.addEventListener('submit', function(e) {
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

    // IMPORTANT: Only target the sidebar navigation links, not the top navbar
    const sidebarNavLinks = document.querySelectorAll('.dashboard-sidebar .nav-link');

    sidebarNavLinks.forEach(link => {
        // Remove existing listeners by cloning and replacing
        const newLink = link.cloneNode(true);
        link.parentNode.replaceChild(newLink, link);

        // Add direct onclick property (most reliable method)
        newLink.onclick = function(e) {
            // Special handling for shop links and project submission - let them navigate normally
            if (this.classList.contains('shop-link') || this.classList.contains('project-link') || this.classList.contains('orders-link')) {
                return true; // Allow normal navigation
            }

            e.preventDefault();

            const section = this.getAttribute('data-section');
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
        case 'transactions':
            loadTransactions();
            break;
        case 'quests':
            loadQuests();
            break;
        case 'slack':
            loadSlackSettings();
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
        .then(response => {
            if (response.status === 401) {
                window.location.href = '/login';
                return null;
            }
            if (response.status === 403) {
                throw new Error('You do not have permission to view posts');
            }
            return response.json();
        })
        .then(data => {
            if (!data) return;
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
            console.error('Error loading posts:', error);
            const postsList = document.getElementById('postsList');
            if (postsList) {
                postsList.innerHTML = '<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><h3>Error Loading Posts</h3><p>' + error.message + '</p></div>';
            }
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
        .then(response => {
            if (response.status === 401) {
                window.location.href = '/login';
                return null;
            }
            if (response.status === 403) {
                throw new Error('You do not have permission to view assignments');
            }
            return response.json();
        })
        .then(data => {
            if (!data) return;
            const assignmentsList = document.getElementById('assignmentsList');
            const assignmentsCount = document.getElementById('assignmentsCount');

            if (assignmentsList) assignmentsList.innerHTML = '';

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
                    if (assignmentsList) assignmentsList.appendChild(card);
                });

                if (assignmentsCount) assignmentsCount.textContent = data.assignments.filter(a => a.status === 'active').length;
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-clipboard-list');
                const title = createElement('h3', '', 'No assignments yet');
                const description = createElement('p', '', 'Create your first assignment to get started!');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                if (assignmentsList) assignmentsList.appendChild(emptyState);

                if (assignmentsCount) assignmentsCount.textContent = '0';
            }
        })
        .catch(error => {
            console.error('Error loading assignments:', error);
            const assignmentsList = document.getElementById('assignmentsList');
            if (assignmentsList) {
                assignmentsList.innerHTML = '<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><h3>Error Loading Assignments</h3><p>' + error.message + '</p></div>';
            }
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
        .then(response => {
            if (response.status === 401) {
                window.location.href = '/login';
                return null;
            }
            if (response.status === 403) {
                throw new Error('You do not have permission to view meetings');
            }
            return response.json();
        })
        .then(data => {
            if (!data) return;
            const meetingsList = document.getElementById('meetingsList');
            const meetingsCount = document.getElementById('meetingsCount');

            if (meetingsList) meetingsList.innerHTML = '';

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
                    if (meetingsList) meetingsList.appendChild(card);
                });

                const thisMonth = new Date().getMonth();
                const thisYear = new Date().getFullYear();
                const thisMonthMeetings = data.meetings.filter(m => {
                    const meetingDate = new Date(m.meeting_date);
                    return meetingDate.getMonth() === thisMonth && meetingDate.getFullYear() === thisYear;
                });
                if (meetingsCount) meetingsCount.textContent = thisMonthMeetings.length;
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-calendar-times');
                const title = createElement('h3', '', 'No meetings scheduled');
                const description = createElement('p', '', 'Schedule your first club meeting to get started!');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                if (meetingsList) meetingsList.appendChild(emptyState);

                if (meetingsCount) meetingsCount.textContent = '0';
            }
        })
        .catch(error => {
            console.error('Error loading meetings:', error);
            const meetingsList = document.getElementById('meetingsList');
            if (meetingsList) {
                meetingsList.innerHTML = '<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><h3>Error Loading Meetings</h3><p>' + error.message + '</p></div>';
            }
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

                if (projectsCount) projectsCount.textContent = data.projects.length;
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-code');
                const title = createElement('h3', '', 'No projects yet');
                const description = createElement('p', '', 'Members can start creating projects to showcase here!');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                projectsList.appendChild(emptyState);

                if (projectsCount) projectsCount.textContent = '0';
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
        .then(response => {
            if (response.status === 401) {
                window.location.href = '/login';
                return null;
            }
            if (response.status === 403) {
                throw new Error('You do not have permission to view resources');
            }
            return response.json();
        })
        .then(data => {
            if (!data) return;
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
            console.error('Error loading resources:', error);
            const resourcesList = document.getElementById('resourcesList');
            if (resourcesList) {
                resourcesList.innerHTML = '<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><h3>Error Loading Resources</h3><p>' + error.message + '</p></div>';
            }
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
                    loadResources();
                    showToast('success', 'Resource deleted successfully', 'Resource Deleted');
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

function deleteResourceDesktop(id, title) {
    deleteResource(id, title);
}

function deleteAssignmentDesktop(id, title) {
    deleteAssignment(id, title);
}

function deleteMeetingDesktop(id, title) {
    deleteMeeting(id, title);
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

// Global variable to prevent duplicate requests
let settingsUpdateInProgress = false;

// Update club settings with email verification workflow
function updateClubSettings(clubName, clubDescription, clubLocation) {
    if (!clubId) {
        showToast('error', 'Cannot update settings: Club ID is missing.', 'Error');
        return;
    }

    // Prevent duplicate requests
    if (settingsUpdateInProgress) {
        return;
    }
    
    settingsUpdateInProgress = true;

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
    })
    .finally(() => {
        // Reset the progress flag
        settingsUpdateInProgress = false;
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
        modal.style.cssText = 'display: none; position: fixed; z-index: 10000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); overflow: auto;';
        modal.innerHTML = `
            <div class="modal-content" style="background-color: var(--surface); margin: 10% auto; padding: 0; border-radius: var(--border-radius); max-width: 500px; width: 90%; box-shadow: var(--shadow-hover); position: relative;">
                <div class="modal-header" style="padding: 1.5rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center;">
                    <h3 style="margin: 0; color: var(--text);"><i class="fas fa-envelope"></i> Email Verification Required</h3>
                    <button class="close" onclick="closeEmailVerificationModal()" style="background: none; border: none; font-size: 1.5rem; font-weight: bold; color: var(--text-secondary); cursor: pointer;">&times;</button>
                </div>
                <div class="modal-body" style="padding: 1.5rem;">
                    <div style="background: #fef3c7; border: 1px solid #f59e0b; border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem;">
                        <p style="margin: 0; color: #92400e; font-size: 0.9rem; display: flex; align-items: center; gap: 0.5rem;">
                            <i class="fas fa-info-circle" style="color: #f39c12;"></i>
                            A verification code is being sent to your email address. Please check your inbox and enter the code below.
                        </p>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="verificationCode">Verification Code *</label>
                        <input type="text" id="verificationCode" class="form-control" placeholder="Enter 5-digit code" maxlength="5" pattern="[0-9]{5}" style="text-align: center; font-size: 1.2rem; letter-spacing: 0.2rem;">
                        <small style="color: #64748b; font-size: 0.875rem; margin-top: 0.5rem; display: block;">
                            <i class="fas fa-clock"></i> Code expires in 10 minutes
                        </small>
                    </div>
                </div>
                <div class="modal-footer" style="padding: 1rem 1.5rem; border-top: 1px solid var(--border); display: flex; justify-content: flex-end; gap: 1rem;">
                    <button type="button" class="btn btn-secondary" onclick="closeEmailVerificationModal()">
                        <i class="fas fa-times"></i> Cancel
                    </button>
                    <button type="button" class="btn btn-primary" onclick="verifyCodeAndUpdateSettings('${clubName.replace(/'/g, "\\'")}', '${clubDescription.replace(/'/g, "\\'")}', '${clubLocation.replace(/'/g, "\\'")}')">
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

    // Focus on the input field
    setTimeout(() => {
        document.getElementById('verificationCode').focus();
    }, 100);

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

// Global variables for transactions pagination
let currentTransactionsPage = 1;
let totalTransactionsPages = 1;

function loadTransactions(page = 1) {
    if (!clubId) {
        console.warn('loadTransactions: clubId is missing. Skipping fetch.');
        const transactionsList = document.getElementById('transactionsList');
        if (transactionsList) transactionsList.textContent = 'Error: Club information is unavailable to load transactions.';
        return;
    }

    // Hide notification when user visits transactions tab
    hideTransactionNotification();

    const typeFilter = document.getElementById('transactionTypeFilter')?.value || '';
    const dateFilter = document.getElementById('transactionDateFilter')?.value || '';

    const params = new URLSearchParams({
        page: page.toString(),
        per_page: '25'
    });

    if (typeFilter) params.append('type', typeFilter);
    if (dateFilter) params.append('date_range', dateFilter);

    fetch(`/api/clubs/${clubId}/transactions?${params}`)
        .then(response => {
            if (response.status === 401) {
                // Authentication failed - redirect to login
                window.location.href = '/login';
                return null;
            }
            if (response.status === 403) {
                // Authorization failed - show error message
                throw new Error('You do not have permission to view transactions');
            }
            return response.json();
        })
        .then(data => {
            if (!data) return; // Handle null case from auth failure
            const transactionsList = document.getElementById('transactionsList');
            const pagination = document.getElementById('transactionsPagination');

            transactionsList.innerHTML = '';

            if (data.transactions && data.transactions.length > 0) {
                // Update pagination info
                currentTransactionsPage = data.pagination.page;
                totalTransactionsPages = data.pagination.pages;

                data.transactions.forEach(transaction => {
                    const transactionCard = createTransactionCard(transaction);
                    transactionsList.appendChild(transactionCard);
                });

                // Update pagination controls
                updateTransactionsPagination(data);
                pagination.style.display = 'flex';

            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-receipt');
                const title = createElement('h3', '', 'No transactions yet');
                const description = createElement('p', '', 'Transaction history will appear here when you earn or spend tokens.');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                transactionsList.appendChild(emptyState);

                pagination.style.display = 'none';
            }
        })
        .catch(error => {
            console.error('Error loading transactions:', error);
            showToast('error', 'Failed to load transactions', 'Error');
        });
}

function createTransactionCard(transaction) {
    const card = createElement('div', 'transaction-card');

    const isPositive = transaction.amount > 0;
    const amountClass = isPositive ? 'positive' : 'negative';
    const amountSign = isPositive ? '+' : '';

    card.innerHTML = `
        <div class="transaction-header">
            <div class="transaction-icon ${transaction.transaction_type}">
                <i class="fas ${getTransactionIcon(transaction.transaction_type)}"></i>
            </div>
            <div class="transaction-info">
                <h4 class="transaction-description">${escapeHtml(transaction.description)}</h4>
                <div class="transaction-meta">
                    <span class="transaction-type">${transaction.transaction_type.charAt(0).toUpperCase() + transaction.transaction_type.slice(1)}</span>
                    ${transaction.user ? `<span class="transaction-user">by ${escapeHtml(transaction.user.username || transaction.user.first_name + ' ' + transaction.user.last_name || transaction.user.email)}</span>` : ''}
                    <span class="transaction-date">${new Date(transaction.created_at).toLocaleDateString()}</span>
                </div>
            </div>
            <div class="transaction-amount ${amountClass}">
                ${amountSign}${Math.abs(transaction.amount).toFixed(0)} tokens
            </div>
        </div>
    `;

    return card;
}

function getTransactionIcon(type) {
    const icons = {
        'credit': 'fa-plus-circle',
        'debit': 'fa-minus-circle',
        'grant': 'fa-gift',
        'purchase': 'fa-shopping-cart',
        'refund': 'fa-undo',
        'manual': 'fa-edit'
    };
    return icons[type] || 'fa-exchange-alt';
}

function updateTransactionsPagination(data) {
    const prevBtn = document.getElementById('prevPage');
    const nextBtn = document.getElementById('nextPage');
    const pageInfo = document.getElementById('pageInfo');

    if (prevBtn && nextBtn && pageInfo) {
        prevBtn.disabled = !data.pagination.has_prev;
        nextBtn.disabled = !data.pagination.has_next;
        pageInfo.textContent = `Page ${data.pagination.page} of ${data.pagination.pages}`;

        // Update onclick handlers
        prevBtn.onclick = () => {
            if (data.pagination.has_prev) {
                loadTransactions(data.pagination.page - 1);
            }
        };

        nextBtn.onclick = () => {
            if (data.pagination.has_next) {
                loadTransactions(data.pagination.page + 1);
            }
        };
    }
}

// Transaction notification functionality
let lastTransactionCount = 0;
let transactionCheckInterval = null;

function checkForNewTransactions() {
    if (!clubId) return;

    fetch(`/api/clubs/${clubId}/transactions?page=1&per_page=1`)
        .then(response => {
            if (response.status === 401 || response.status === 403) {
                // Authentication/authorization failed, stop checking
                console.warn('Transaction check failed due to auth, stopping notifications');
                if (transactionCheckInterval) {
                    clearInterval(transactionCheckInterval);
                    transactionCheckInterval = null;
                }
                return null;
            }
            return response.json();
        })
        .then(data => {
            if (data && data.pagination && data.pagination.total > lastTransactionCount) {
                if (lastTransactionCount > 0) { // Don't show on first load
                    showTransactionNotification();
                }
                lastTransactionCount = data.pagination.total;
                localStorage.setItem(`club_${clubId}_transaction_count`, lastTransactionCount);
            }
        })
        .catch(error => {
            console.error('Error checking for new transactions:', error);
            // Stop checking if there are repeated errors
            if (transactionCheckInterval) {
                clearInterval(transactionCheckInterval);
                transactionCheckInterval = null;
            }
        });
}

function showTransactionNotification() {
    const notificationDot = document.getElementById('transactionsNotification');
    if (notificationDot) {
        notificationDot.style.display = 'block';
    }
}

function hideTransactionNotification() {
    const notificationDot = document.getElementById('transactionsNotification');
    if (notificationDot) {
        notificationDot.style.display = 'none';
    }
}

function initializeTransactionNotifications() {
    // Load last known transaction count from localStorage
    const storedCount = localStorage.getItem(`club_${clubId}_transaction_count`);
    if (storedCount) {
        lastTransactionCount = parseInt(storedCount);
    }

    // Check for new transactions immediately
    checkForNewTransactions();

    // Set up periodic checking every 30 seconds
    transactionCheckInterval = setInterval(checkForNewTransactions, 30000);
}

// Initialize transaction filters
document.addEventListener('DOMContentLoaded', function() {
    const typeFilter = document.getElementById('transactionTypeFilter');
    const dateFilter = document.getElementById('transactionDateFilter');

    if (typeFilter) {
        typeFilter.addEventListener('change', () => loadTransactions(1));
    }

    if (dateFilter) {
        dateFilter.addEventListener('change', () => loadTransactions(1));
    }

    // Initialize transaction notifications
    if (clubId) {
        initializeTransactionNotifications();
    }
});

// Quest Management Functions
async function loadQuestData() {
    if (!clubId) return;

    try {
        const response = await fetch(`/api/club/${clubId}/quests`);
        
        if (response.status === 401) {
            window.location.href = '/login';
            return;
        }
        
        const data = await response.json();

        if (response.ok) {
            updateQuestDisplay(data);
            updateQuestTimer(data.time_remaining);
        } else {
            console.error('Failed to load quest data:', data.error);
        }
    } catch (error) {
        console.error('Error loading quest data:', error);
    }
}

function updateQuestDisplay(data) {
    const quests = data.quests;

    quests.forEach(quest => {
        if (quest.quest_type === 'gallery_post') {
            updateGalleryQuestDisplay(quest);
        } else if (quest.quest_type === 'member_projects') {
            updateMemberProjectsQuestDisplay(quest);
        }
    });
}

function updateGalleryQuestDisplay(quest) {
    const progressFill = document.getElementById('galleryProgress');
    const progressText = document.getElementById('galleryProgressText');
    const status = document.getElementById('galleryStatus');

    if (progressFill) {
        progressFill.style.width = `${quest.percentage}%`;
    }

    if (progressText) {
        progressText.textContent = `${quest.progress}/${quest.target} posts`;
    }

    if (status) {
        if (quest.completed) {
            status.textContent = 'Completed';
            status.className = 'quest-status completed';
        } else {
            status.textContent = 'Pending';
            status.className = 'quest-status pending';
        }
    }
}

function updateMemberProjectsQuestDisplay(quest) {
    const progressFill = document.getElementById('membersProgress');
    const progressText = document.getElementById('membersProgressText');
    const status = document.getElementById('membersStatus');

    if (progressFill) {
        progressFill.style.width = `${quest.percentage}%`;
    }

    if (progressText) {
        progressText.textContent = `${quest.progress}/${quest.target} members`;
    }

    if (status) {
        if (quest.completed) {
            status.textContent = 'Completed';
            status.className = 'quest-status completed';
        } else {
            status.textContent = 'Pending';
            status.className = 'quest-status pending';
        }
    }
}

function updateQuestTimer(timeRemaining) {
    const timerElement = document.getElementById('questTimer');
    if (!timerElement) return;

    function formatTime() {
        const days = timeRemaining.days;
        const hours = timeRemaining.hours;
        const minutes = timeRemaining.minutes;

        if (days > 0) {
            return `${days}d ${hours}h ${minutes}m`;
        } else if (hours > 0) {
            return `${hours}h ${minutes}m`;
        } else {
            return `${minutes}m`;
        }
    }

    timerElement.textContent = formatTime();

    // Update the timer every minute
    setInterval(() => {
        // Decrease the time remaining
        timeRemaining.minutes--;
        if (timeRemaining.minutes < 0) {
            timeRemaining.minutes = 59;
            timeRemaining.hours--;
            if (timeRemaining.hours < 0) {
                timeRemaining.hours = 23;
                timeRemaining.days--;
                if (timeRemaining.days < 0) {
                    // Week has reset, reload quest data
                    loadQuestData();
                    return;
                }
            }
        }
        timerElement.textContent = formatTime();
    }, 60000); // Update every minute
}

// Transfer leadership functionality
function initiateLeadershipTransfer() {
    const newLeaderSelect = document.getElementById('newLeaderSelect');
    const selectedUserId = newLeaderSelect.value;
    const selectedUserText = newLeaderSelect.options[newLeaderSelect.selectedIndex].text;

    if (!selectedUserId) {
        showToast('error', 'Please select a member to become the new leader');
        return;
    }

    // Parse username and email from the option text
    const match = selectedUserText.match(/^(.+?) \((.+?)\)$/);
    if (match) {
        const username = match[1];
        const email = match[2];

        // Update the modal with the selected user info
        document.getElementById('newLeaderAvatar').textContent = username.charAt(0).toUpperCase();
        document.getElementById('newLeaderName').textContent = username;
        document.getElementById('newLeaderEmail').textContent = email;

        // Store the user ID for later use
        document.getElementById('confirmTransferButton').setAttribute('data-user-id', selectedUserId);

        // Show the transfer confirmation modal
        document.getElementById('transferLeadershipModal').style.display = 'block';

        // Reset the confirmation input
        document.getElementById('transferConfirmationInput').value = '';
        document.getElementById('confirmTransferButton').disabled = true;
    }
}

// Slack Integration Functions
async function loadSlackSettings() {
    try {
        const response = await fetch(`/api/club/${clubId}/slack/settings`);
        const data = await response.json();

        if (data.settings) {
            // Populate form with existing settings
            document.getElementById('slackChannelId').value = data.settings.channel_id || '';
            document.getElementById('slackChannelName').value = data.settings.channel_name || '';
            document.getElementById('slackIsPublic').checked = data.settings.is_public !== false;

            // Show invite section if channel is configured
            if (data.settings.channel_id) {
                document.getElementById('slackInviteCard').style.display = 'block';
                document.getElementById('currentChannelInfo').style.display = 'block';
                document.getElementById('displayChannelName').textContent = data.settings.channel_name || '#your-channel';
                document.getElementById('displayChannelId').textContent = data.settings.channel_id;
            }
        }
    } catch (error) {
        console.error('Error loading Slack settings:', error);
    }
}

async function saveSlackSettings(event) {
    event.preventDefault();

    const channelId = document.getElementById('slackChannelId').value.trim();
    const channelName = document.getElementById('slackChannelName').value.trim();
    const isPublic = document.getElementById('slackIsPublic').checked;

    if (!channelId) {
        showToast('error', 'Channel ID is required');
        return;
    }

    if (!channelId.startsWith('C')) {
        showToast('error', 'Invalid channel ID format. Should start with "C"');
        return;
    }

    try {
        const response = await fetch(`/api/club/${clubId}/slack/settings`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                channel_id: channelId,
                channel_name: channelName,
                is_public: isPublic
            })
        });

        const data = await response.json();

        if (response.ok) {
            showToast('success', 'Slack settings saved successfully!');

            // Show invite section
            document.getElementById('slackInviteCard').style.display = 'block';
            document.getElementById('currentChannelInfo').style.display = 'block';
            document.getElementById('displayChannelName').textContent = channelName || '#your-channel';
            document.getElementById('displayChannelId').textContent = channelId;
        } else {
            showToast('error', data.error || 'Failed to save Slack settings');
        }
    } catch (error) {
        console.error('Error saving Slack settings:', error);
        showToast('error', 'Failed to save Slack settings');
    }
}

async function bulkInviteToSlack() {
    // Get current channel info
    const channelName = document.getElementById('displayChannelName').textContent;
    const channelId = document.getElementById('displayChannelId').textContent;
    
    // Update modal with current channel info
    document.getElementById('bulkInviteChannelName').textContent = channelName;
    document.getElementById('bulkInviteChannelId').textContent = channelId;
    
    // Show confirmation modal
    document.getElementById('slackBulkInviteModal').style.display = 'block';
}

async function confirmBulkInvite() {
    const bulkInviteButton = document.querySelector('#slackBulkInviteModal .btn-primary');
    const originalContent = bulkInviteButton.innerHTML;
    
    // Show loading state
    bulkInviteButton.disabled = true;
    bulkInviteButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending Invitations...';
    
    try {
        const response = await fetch(`/api/club/${clubId}/slack/bulk-invite`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        // Close confirmation modal
        closeSlackBulkInviteModal();

        if (response.ok) {
            let resultHtml = `
                <div style="color: #10b981; margin-bottom: 1rem;">
                    <i class="fas fa-check-circle"></i> <strong>Success!</strong>
                </div>
                <p><strong>${data.success_count}</strong> out of <strong>${data.total_members}</strong> members invited successfully.</p>
            `;
            
            if (data.failed_invitations && data.failed_invitations.length > 0) {
                resultHtml += `
                    <div style="margin-top: 1rem;">
                        <p><strong>Failed invitations (${data.failed_invitations.length}):</strong></p>
                        <ul style="margin: 0; padding-left: 1.5rem;">
                            ${data.failed_invitations.map(email => `<li>${email}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }
            
            showSlackInviteResult(resultHtml);
        } else {
            showSlackInviteResult(`
                <div style="color: #ef4444; margin-bottom: 1rem;">
                    <i class="fas fa-times-circle"></i> <strong>Error</strong>
                </div>
                <p>${data.error || 'Failed to send bulk invitations'}</p>
            `);
        }
    } catch (error) {
        console.error('Error sending bulk invitations:', error);
        closeSlackBulkInviteModal();
        showSlackInviteResult(`
            <div style="color: #ef4444; margin-bottom: 1rem;">
                <i class="fas fa-times-circle"></i> <strong>Error</strong>
            </div>
            <p>Failed to send bulk invitations. Please try again.</p>
        `);
    } finally {
        // Restore button state
        bulkInviteButton.disabled = false;
        bulkInviteButton.innerHTML = originalContent;
    }
}

function closeSlackBulkInviteModal() {
    document.getElementById('slackBulkInviteModal').style.display = 'none';
}

function showSlackInviteResult(content) {
    document.getElementById('slackInviteResultContent').innerHTML = content;
    document.getElementById('slackInviteResultModal').style.display = 'block';
}

function closeSlackInviteResultModal() {
    document.getElementById('slackInviteResultModal').style.display = 'none';
}

async function inviteIndividualToSlack() {
    const selectElement = document.getElementById('individualInviteSelect');
    const email = selectElement.value.trim();
    const selectedText = selectElement.options[selectElement.selectedIndex].text;
    const inviteButton = document.querySelector('button[onclick="inviteIndividualToSlack()"]');

    if (!email) {
        showSlackInviteResult(`
            <div style="color: #f59e0b; margin-bottom: 1rem;">
                <i class="fas fa-exclamation-triangle"></i> <strong>No Selection</strong>
            </div>
            <p>Please select a member to invite.</p>
        `);
        return;
    }

    // Show loading state
    const originalContent = inviteButton.innerHTML;
    inviteButton.disabled = true;
    inviteButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';

    try {
        const response = await fetch(`/api/club/${clubId}/slack/invite`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: email
            })
        });

        const data = await response.json();

        if (response.ok) {
            showSlackInviteResult(`
                <div style="color: #10b981; margin-bottom: 1rem;">
                    <i class="fas fa-check-circle"></i> <strong>Success!</strong>
                </div>
                <p>Successfully invited <strong>${selectedText}</strong> to the Slack channel.</p>
            `);
            selectElement.value = '';
        } else {
            showSlackInviteResult(`
                <div style="color: #ef4444; margin-bottom: 1rem;">
                    <i class="fas fa-times-circle"></i> <strong>Error</strong>
                </div>
                <p>${data.error || 'Failed to send invitation'}</p>
            `);
        }
    } catch (error) {
        console.error('Error sending individual invitation:', error);
        showSlackInviteResult(`
            <div style="color: #ef4444; margin-bottom: 1rem;">
                <i class="fas fa-times-circle"></i> <strong>Error</strong>
            </div>
            <p>Failed to send invitation. Please try again.</p>
        `);
    } finally {
        // Restore button state
        inviteButton.disabled = false;
        inviteButton.innerHTML = originalContent;
    }
}

async function inviteByEmailToSlack() {
    const emailInput = document.getElementById('inviteByEmailInput');
    const email = emailInput.value.trim();
    const emailInviteButton = document.querySelector('button[onclick="inviteByEmailToSlack()"]');

    if (!email) {
        showSlackInviteResult(`
            <div style="color: #f59e0b; margin-bottom: 1rem;">
                <i class="fas fa-exclamation-triangle"></i> <strong>No Email</strong>
            </div>
            <p>Please enter an email address to invite.</p>
        `);
        return;
    }

    if (!email.includes('@')) {
        showSlackInviteResult(`
            <div style="color: #f59e0b; margin-bottom: 1rem;">
                <i class="fas fa-exclamation-triangle"></i> <strong>Invalid Email</strong>
            </div>
            <p>Please enter a valid email address.</p>
        `);
        return;
    }

    // Show loading state
    const originalContent = emailInviteButton.innerHTML;
    emailInviteButton.disabled = true;
    emailInviteButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';

    try {
        const response = await fetch(`/api/club/${clubId}/slack/invite`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: email
            })
        });

        const data = await response.json();

        if (response.ok) {
            showSlackInviteResult(`
                <div style="color: #10b981; margin-bottom: 1rem;">
                    <i class="fas fa-check-circle"></i> <strong>Success!</strong>
                </div>
                <p>Successfully invited <strong>${email}</strong> to the Slack channel.</p>
            `);
            emailInput.value = '';
        } else {
            showSlackInviteResult(`
                <div style="color: #ef4444; margin-bottom: 1rem;">
                    <i class="fas fa-times-circle"></i> <strong>Error</strong>
                </div>
                <p>${data.error || 'Failed to send invitation'}</p>
            `);
        }
    } catch (error) {
        console.error('Error sending email invitation:', error);
        showSlackInviteResult(`
            <div style="color: #ef4444; margin-bottom: 1rem;">
                <i class="fas fa-times-circle"></i> <strong>Error</strong>
            </div>
            <p>Failed to send invitation. Please try again.</p>
        `);
    } finally {
        // Restore button state
        emailInviteButton.disabled = false;
        emailInviteButton.innerHTML = originalContent;
    }
}

// Co-leader management functions
function promoteToCoLeader(userId, username) {
    if (!clubId) {
        showToast('error', 'Cannot promote member: Club ID is missing.', 'Error');
        return;
    }

    showConfirmModal(
        `Promote ${username} to Co-Leader?`,
        'This will give them management privileges for the club.',
        () => {
            // First attempt without email verification
            fetch(`/api/clubs/${clubId}/co-leader`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    user_id: userId
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast('success', 'Member promoted to co-leader successfully', 'Promoted');
                    // Reload the page to update the members list
                    window.location.reload();
                } else if (data.error && data.error.includes('Email verification required')) {
                    // Show verification modal and send code
                    showEmailVerificationModalForCoLeader(userId, username, 'promote');
                } else {
                    showToast('error', data.error || 'Failed to promote member', 'Error');
                }
            })
            .catch(error => {
                console.error('Error promoting member:', error);
                showToast('error', 'Error promoting member', 'Error');
            });
        }
    );
}

function removeCoLeader() {
    if (!clubId) {
        showToast('error', 'Cannot remove co-leader: Club ID is missing.', 'Error');
        return;
    }

    showConfirmModal(
        'Remove Co-Leader?',
        'This will revoke their management privileges.',
        () => {
            // First attempt without email verification
            fetch(`/api/clubs/${clubId}/co-leader`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast('success', 'Co-leader removed successfully', 'Removed');
                    // Reload the page to update the members list
                    window.location.reload();
                } else if (data.error && data.error.includes('Email verification required')) {
                    // Show verification modal and send code
                    showEmailVerificationModalForCoLeader(null, null, 'remove');
                } else {
                    showToast('error', data.error || 'Failed to remove co-leader', 'Error');
                }
            })
            .catch(error => {
                console.error('Error removing co-leader:', error);
                showToast('error', 'Error removing co-leader', 'Error');
            });
        }
    );
}

// Email verification modal for co-leader management
function showEmailVerificationModalForCoLeader(userId, username, action) {
    // Create modal HTML if it doesn't exist
    let modal = document.getElementById('coLeaderVerificationModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'coLeaderVerificationModal';
        modal.className = 'modal';
        modal.style.cssText = 'display: none; position: fixed; z-index: 10000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); overflow: auto;';
        modal.innerHTML = `
            <div class="modal-content" style="background-color: var(--surface); margin: 10% auto; padding: 0; border-radius: var(--border-radius); max-width: 500px; width: 90%; box-shadow: var(--shadow-hover); position: relative;">
                <div class="modal-header" style="padding: 1.5rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center;">
                    <h3 style="margin: 0; color: var(--text);"><i class="fas fa-envelope"></i> Email Verification Required</h3>
                    <button class="close" onclick="closeCoLeaderVerificationModal()" style="background: none; border: none; font-size: 1.5rem; font-weight: bold; color: var(--text-secondary); cursor: pointer;">&times;</button>
                </div>
                <div class="modal-body" style="padding: 1.5rem;">
                    <div style="background: #fef3c7; border: 1px solid #f59e0b; border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem;">
                        <p style="margin: 0; color: #92400e; font-size: 0.9rem; display: flex; align-items: center; gap: 0.5rem;">
                            <i class="fas fa-info-circle" style="color: #f39c12;"></i>
                            A verification code is being sent to your email address. Please check your inbox and enter the code below.
                        </p>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="coLeaderVerificationCode">Verification Code *</label>
                        <input type="text" id="coLeaderVerificationCode" class="form-control" placeholder="Enter 5-digit code" maxlength="5" pattern="[0-9]{5}" style="text-align: center; font-size: 1.2rem; letter-spacing: 0.2rem;">
                        <small style="color: #64748b; font-size: 0.875rem; margin-top: 0.5rem; display: block;">
                            <i class="fas fa-clock"></i> Code expires in 10 minutes
                        </small>
                    </div>
                </div>
                <div class="modal-footer" style="padding: 1rem 1.5rem; border-top: 1px solid var(--border); display: flex; justify-content: flex-end; gap: 1rem;">
                    <button type="button" class="btn btn-secondary" onclick="closeCoLeaderVerificationModal()">
                        <i class="fas fa-times"></i> Cancel
                    </button>
                    <button type="button" class="btn btn-primary" onclick="verifyCodeAndManageCoLeader()">
                        <i class="fas fa-check"></i> Verify & Continue
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }

    // Store the action and user info for later use
    modal.setAttribute('data-action', action);
    if (userId) modal.setAttribute('data-user-id', userId);
    if (username) modal.setAttribute('data-username', username);

    // Clear previous code and show modal
    document.getElementById('coLeaderVerificationCode').value = '';
    modal.style.display = 'block';

    // Focus on the input field
    setTimeout(() => {
        document.getElementById('coLeaderVerificationCode').focus();
    }, 100);

    // Send verification code
    sendVerificationCodeForCoLeader();
}

// Send verification code for co-leader management
function sendVerificationCodeForCoLeader() {
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

// Close co-leader verification modal
function closeCoLeaderVerificationModal() {
    const modal = document.getElementById('coLeaderVerificationModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Verify code and manage co-leader
function verifyCodeAndManageCoLeader() {
    const modal = document.getElementById('coLeaderVerificationModal');
    const verificationCode = document.getElementById('coLeaderVerificationCode').value;
    const action = modal.getAttribute('data-action');
    const userId = modal.getAttribute('data-user-id');
    const username = modal.getAttribute('data-username');

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
            // Step 2: Now perform the co-leader action with email_verified flag
            const requestBody = {
                email_verified: true
            };
            
            if (action === 'promote') {
                requestBody.user_id = userId;
            }

            return fetch(`/api/clubs/${clubId}/co-leader`, {
                method: action === 'promote' ? 'POST' : 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(requestBody)
            });
        } else {
            throw new Error(data.error || 'Email verification failed');
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            closeCoLeaderVerificationModal();
            const actionText = action === 'promote' ? 'promoted to co-leader' : 'removed as co-leader';
            showToast('success', `Member ${actionText} successfully`, 'Success');
            // Reload the page to update the members list
            window.location.reload();
        } else {
            showToast('error', data.error || `Failed to ${action} co-leader`, 'Error');
        }
    })
    .catch(error => {
        console.error('Error in verification process:', error);
        showToast('error', error.message || 'Error managing co-leader', 'Error');
    });
}

function confirmRemoveMember(userId, username) {
    if (!clubId) {
        showToast('error', 'Cannot remove member: Club ID is missing.', 'Error');
        return;
    }

    showConfirmModal(
        `Remove ${username} from the club?`,
        'This action cannot be undone.',
        () => {
            fetch(`/api/clubs/${clubId}/members/${userId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast('success', 'Member removed successfully', 'Member Removed');
                    // Reload the page to update the members list
                    window.location.reload();
                } else {
                    showToast('error', data.error || 'Failed to remove member', 'Error');
                }
            })
            .catch(error => {
                console.error('Error removing member:', error);
                showToast('error', 'Error removing member', 'Error');
            });
        }
    );
}

// Slack form event listener
const slackForm = document.getElementById('slackSettingsForm');
if (slackForm) {
    slackForm.addEventListener('submit', saveSlackSettings);
}

// Club settings form event listener
const clubSettingsForm = document.getElementById('clubSettingsForm');
if (clubSettingsForm) {
    clubSettingsForm.addEventListener('submit', updateClubSettings);
}

// Transfer confirmation input event listener
const transferConfirmationInput = document.getElementById('transferConfirmationInput');
if (transferConfirmationInput) {
    transferConfirmationInput.addEventListener('input', function() {
        const input = this.value.trim();
        const button = document.getElementById('confirmTransferButton');
        if (button) {
            button.disabled = input !== 'TRANSFER';
        }
    });
}