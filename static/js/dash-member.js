
// Member-specific dashboard JavaScript
let clubId = '';
let joinCode = '';

document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing member club dashboard...');

    const dashboardElement = document.querySelector('.club-dashboard');
    if (dashboardElement) {
        clubId = dashboardElement.dataset.clubId || '';
        joinCode = dashboardElement.dataset.joinCode || '';
        console.log('Retrieved Club ID:', clubId);
        console.log('Retrieved Join Code:', joinCode);
    }

    initNavigation();

    if (clubId) {
        loadMemberData();
    }
});

function initNavigation() {
    console.log('Setting up member navigation...');

    const sidebarNavLinks = document.querySelectorAll('.dashboard-sidebar .nav-link');
    
    sidebarNavLinks.forEach(link => {
        const newLink = link.cloneNode(true);
        link.parentNode.replaceChild(newLink, link);

        newLink.onclick = function(e) {
            e.preventDefault();
            const section = this.getAttribute('data-section');
            if (section) {
                openTab(section);
                return false;
            }
        };
    });

    const hash = window.location.hash.substring(1);
    if (hash) {
        openTab(hash);
    } else {
        openTab('dashboard');
    }
}

function openTab(sectionName) {
    if (!sectionName) return;

    console.log('Opening member tab:', sectionName);

    const allSections = document.querySelectorAll('.club-section');
    allSections.forEach(section => {
        section.classList.remove('active');
    });

    const targetSection = document.getElementById(sectionName);
    if (targetSection) {
        targetSection.classList.add('active');
    } else {
        console.warn('Section not found:', sectionName);
        return;
    }

    const allNavLinks = document.querySelectorAll('.nav-link');
    allNavLinks.forEach(link => {
        link.classList.remove('active');
    });

    const activeNavLink = document.querySelector(`.nav-link[data-section="${sectionName}"]`);
    if (activeNavLink) {
        activeNavLink.classList.add('active');
    }

    loadMemberSectionData(sectionName);
}

function loadMemberData() {
    if (!clubId) return;

    loadMemberPosts();
    loadMemberAssignments();
    loadMemberMeetings();
    loadMemberProjects();
    loadMemberResources();
    loadMemberSubmissions();
}

function loadMemberSectionData(section) {
    switch(section) {
        case 'stream':
            loadMemberPosts();
            break;
        case 'assignments':
            loadMemberAssignments();
            break;
        case 'schedule':
            loadMemberMeetings();
            break;
        case 'projects':
            loadMemberProjects();
            break;
        case 'resources':
            loadMemberResources();
            break;
        case 'pizza':
            loadMemberSubmissions();
            break;
    }
}

function loadMemberPosts() {
    if (!clubId) return;
    
    fetch(`/api/clubs/${clubId}/posts`)
        .then(response => response.json())
        .then(data => {
            const postsList = document.getElementById('postsList');
            postsList.innerHTML = '';

            if (data.posts && data.posts.length > 0) {
                data.posts.forEach(post => {
                    const postCard = document.createElement('div');
                    postCard.className = 'post-card';
                    
                    postCard.innerHTML = `
                        <div class="post-header">
                            <div class="post-avatar">${post.user.username[0].toUpperCase()}</div>
                            <div class="post-info">
                                <h4>${post.user.username}</h4>
                                <div class="post-date">${new Date(post.created_at).toLocaleDateString()}</div>
                            </div>
                        </div>
                        <div class="post-content">
                            <p>${post.content}</p>
                        </div>
                    `;
                    
                    postsList.appendChild(postCard);
                });
            } else {
                postsList.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-stream"></i>
                        <h3>No announcements yet</h3>
                        <p>Your club leaders will post updates here!</p>
                    </div>
                `;
            }
        })
        .catch(error => {
            console.error('Error loading posts:', error);
        });
}

function loadMemberAssignments() {
    if (!clubId) return;
    
    fetch(`/api/clubs/${clubId}/assignments`)
        .then(response => response.json())
        .then(data => {
            const assignmentsList = document.getElementById('assignmentsList');
            const assignmentsCount = document.getElementById('myAssignmentsCount');

            assignmentsList.innerHTML = '';

            if (data.assignments && data.assignments.length > 0) {
                data.assignments.forEach(assignment => {
                    const card = document.createElement('div');
                    card.className = 'card';
                    card.style.marginBottom = '1rem';

                    const isOverdue = assignment.due_date && new Date(assignment.due_date) < new Date();
                    
                    card.innerHTML = `
                        <div class="card-header" style="display: flex; justify-content: space-between; align-items: flex-start;">
                            <div>
                                <h3 style="margin: 0; font-size: 1.125rem; color: #1f2937;">${assignment.title}</h3>
                                <span style="background: ${assignment.status === 'active' ? '#10b981' : '#6b7280'}; color: white; padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; margin-top: 0.5rem; display: inline-block;">${assignment.status}</span>
                                ${isOverdue ? '<span style="background: #ef4444; color: white; padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; margin-left: 0.5rem;">OVERDUE</span>' : ''}
                            </div>
                        </div>
                        <div class="card-body">
                            <p style="margin-bottom: 1rem; color: #6b7280;">${assignment.description}</p>
                            <div style="display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.875rem; color: #6b7280;">
                                ${assignment.due_date ? `<span style="display: flex; align-items: center; gap: 0.25rem;"><i class="fas fa-calendar"></i> Due: ${new Date(assignment.due_date).toLocaleDateString()}</span>` : ''}
                                <span style="display: flex; align-items: center; gap: 0.25rem;"><i class="fas fa-users"></i> ${assignment.for_all_members ? 'All members' : 'Selected members'}</span>
                            </div>
                        </div>
                    `;
                    
                    assignmentsList.appendChild(card);
                });

                if (assignmentsCount) {
                    assignmentsCount.textContent = data.assignments.filter(a => a.status === 'active').length;
                }
            } else {
                assignmentsList.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-clipboard-list"></i>
                        <h3>No assignments yet</h3>
                        <p>Your leaders will assign coding challenges soon!</p>
                    </div>
                `;
                if (assignmentsCount) assignmentsCount.textContent = '0';
            }
        })
        .catch(error => {
            console.error('Error loading assignments:', error);
        });
}

function loadMemberMeetings() {
    if (!clubId) return;
    
    fetch(`/api/clubs/${clubId}/meetings`)
        .then(response => response.json())
        .then(data => {
            const meetingsList = document.getElementById('meetingsList');
            const eventsCount = document.getElementById('upcomingEventsCount');

            meetingsList.innerHTML = '';

            if (data.meetings && data.meetings.length > 0) {
                data.meetings.forEach(meeting => {
                    const card = document.createElement('div');
                    card.className = 'card';
                    card.style.marginBottom = '1rem';
                    
                    card.innerHTML = `
                        <div class="card-header">
                            <h3 style="margin: 0; font-size: 1.125rem; color: #1f2937;">${meeting.title}</h3>
                        </div>
                        <div class="card-body">
                            ${meeting.description ? `<p style="margin-bottom: 1rem; color: #6b7280;">${meeting.description}</p>` : ''}
                            <div style="display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.875rem; color: #6b7280;">
                                <span style="display: flex; align-items: center; gap: 0.25rem;"><i class="fas fa-calendar"></i> ${new Date(meeting.meeting_date).toLocaleDateString()}</span>
                                <span style="display: flex; align-items: center; gap: 0.25rem;"><i class="fas fa-clock"></i> ${meeting.start_time}${meeting.end_time ? ` - ${meeting.end_time}` : ''}</span>
                                ${meeting.location ? `<span style="display: flex; align-items: center; gap: 0.25rem;"><i class="fas fa-map-marker-alt"></i> ${meeting.location}</span>` : ''}
                                ${meeting.meeting_link ? `<span style="display: flex; align-items: center; gap: 0.25rem;"><i class="fas fa-link"></i> <a href="${meeting.meeting_link}" target="_blank" style="color: #ec3750;">Join Meeting</a></span>` : ''}
                            </div>
                        </div>
                    `;
                    
                    meetingsList.appendChild(card);
                });

                if (eventsCount) {
                    const thisMonth = new Date().getMonth();
                    const thisYear = new Date().getFullYear();
                    const thisMonthMeetings = data.meetings.filter(m => {
                        const meetingDate = new Date(m.meeting_date);
                        return meetingDate.getMonth() === thisMonth && meetingDate.getFullYear() === thisYear;
                    });
                    eventsCount.textContent = thisMonthMeetings.length;
                }
            } else {
                meetingsList.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-calendar-times"></i>
                        <h3>No events scheduled</h3>
                        <p>Check back for upcoming club events!</p>
                    </div>
                `;
                if (eventsCount) eventsCount.textContent = '0';
            }
        })
        .catch(error => {
            console.error('Error loading meetings:', error);
        });
}

function loadMemberProjects() {
    if (!clubId) return;
    
    // Load current user's Hackatime projects
    fetch(`/api/hackatime/projects/${window.currentUserId || ''}`)
        .then(response => response.json())
        .then(data => {
            const projectsList = document.getElementById('myHackatimeProjectsList');
            const projectsCount = document.getElementById('myProjectsCount');

            if (data.error) {
                projectsList.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-exclamation-triangle"></i>
                        <h3>Unable to load projects</h3>
                        <p>${data.error}</p>
                    </div>
                `;
                if (projectsCount) projectsCount.textContent = '0';
                return;
            }

            if (data.projects && data.projects.length > 0) {
                let projectsHtml = `<h4 style="margin-bottom: 1rem; color: #1a202c;">Your Hackatime Projects</h4>`;
                
                data.projects.forEach(project => {
                    projectsHtml += `
                        <div class="card" style="margin-bottom: 1rem;">
                            <div class="card-header" style="display: flex; justify-content: space-between; align-items: flex-start;">
                                <h4 style="margin: 0; color: #1a202c; font-size: 1rem;">
                                    <i class="fas fa-code"></i> ${project.name}
                                </h4>
                                <span style="background: #10b981; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600;">${project.formatted_time}</span>
                            </div>
                            <div class="card-body">
                                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.875rem; color: #6b7280;">
                                    <span style="display: flex; align-items: center; gap: 0.25rem;">
                                        <i class="fas fa-clock"></i> ${project.total_seconds.toLocaleString()} seconds
                                    </span>
                                    ${project.percent ? `<span style="display: flex; align-items: center; gap: 0.25rem;"><i class="fas fa-chart-pie"></i> ${project.percent.toFixed(1)}% of total time</span>` : ''}
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                projectsList.innerHTML = projectsHtml;
                if (projectsCount) projectsCount.textContent = data.projects.length;
            } else {
                projectsList.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-clock"></i>
                        <h3>No projects found</h3>
                        <p>You haven't logged any coding time yet on Hackatime</p>
                    </div>
                `;
                if (projectsCount) projectsCount.textContent = '0';
            }
        })
        .catch(error => {
            console.error('Error loading Hackatime projects:', error);
            const projectsList = document.getElementById('myHackatimeProjectsList');
            if (projectsList) {
                projectsList.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-exclamation-triangle"></i>
                        <h3>Error loading projects</h3>
                        <p>Failed to fetch Hackatime data. Please try again.</p>
                    </div>
                `;
            }
        });
}

function loadMemberResources() {
    if (!clubId) return;
    
    fetch(`/api/clubs/${clubId}/resources`)
        .then(response => response.json())
        .then(data => {
            const resourcesList = document.getElementById('resourcesList');
            resourcesList.innerHTML = '';

            if (data.resources && data.resources.length > 0) {
                data.resources.forEach(resource => {
                    const card = document.createElement('div');
                    card.className = 'card';
                    card.style.marginBottom = '1rem';
                    
                    card.innerHTML = `
                        <div class="card-header">
                            <h3 style="margin: 0; font-size: 1.125rem; color: #1f2937;">
                                <i class="fas fa-${resource.icon}"></i> ${resource.title}
                            </h3>
                        </div>
                        <div class="card-body">
                            ${resource.description ? `<p style="margin-bottom: 1rem; color: #6b7280;">${resource.description}</p>` : ''}
                            <div style="display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.875rem; color: #6b7280;">
                                <span style="display: flex; align-items: center; gap: 0.25rem;">
                                    <i class="fas fa-link"></i> 
                                    <a href="${resource.url}" target="_blank" style="color: #ec3750;">Visit Resource</a>
                                </span>
                            </div>
                        </div>
                    `;
                    
                    resourcesList.appendChild(card);
                });
            } else {
                resourcesList.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-book"></i>
                        <h3>No resources yet</h3>
                        <p>Your club leaders will share helpful resources here!</p>
                    </div>
                `;
            }
        })
        .catch(error => {
            console.error('Error loading resources:', error);
        });
}

function loadMemberSubmissions() {
    // This would load the current user's submissions
    const submissionsList = document.getElementById('mySubmissionsList');
    const submissionsCount = document.getElementById('achievementsCount');
    
    if (submissionsList) {
        submissionsList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-hand-holding-usd"></i>
                <h3>No submissions yet</h3>
                <p>Submit your first project to get started!</p>
            </div>
        `;
    }
    
    if (submissionsCount) {
        submissionsCount.textContent = '0';
    }
}

function openPizzaGrantModal() {
    const modal = document.getElementById('pizzaGrantModal');
    if (modal) {
        modal.style.display = 'block';
        loadMemberHackatimeProjectsForGrant();
    }
}

function loadMemberHackatimeProjectsForGrant() {
    const projectSelect = document.getElementById('grantProjectSelect');
    if (!projectSelect) return;

    projectSelect.innerHTML = '<option value="">Loading projects...</option>';

    fetch(`/api/hackatime/projects/${window.currentUserId || ''}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                projectSelect.innerHTML = '<option value="">No Hackatime projects found</option>';
                return;
            }

            projectSelect.innerHTML = '<option value="">Select your project</option>';

            if (data.projects && data.projects.length > 0) {
                data.projects.forEach(project => {
                    if (project.total_seconds >= 3600) { // At least 1 hour
                        const option = document.createElement('option');
                        option.value = project.name;
                        option.textContent = `${project.name} (${project.formatted_time})`;
                        option.dataset.hours = (project.total_seconds / 3600).toFixed(1);
                        projectSelect.appendChild(option);
                    }
                });
            }

            if (projectSelect.children.length === 1) {
                projectSelect.innerHTML = '<option value="">No eligible projects (need 1+ hour)</option>';
            }
        })
        .catch(error => {
            console.error('Error loading projects:', error);
            projectSelect.innerHTML = '<option value="">Error loading projects</option>';
        });
}

// Modal helper functions
function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
    }
}

// Setup modal close handlers
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal')) {
        e.target.style.display = 'none';
    }
    if (e.target.classList.contains('close')) {
        const modal = e.target.closest('.modal');
        if (modal) modal.style.display = 'none';
    }
});
