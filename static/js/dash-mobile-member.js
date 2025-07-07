
// Mobile Member Dashboard JavaScript

class MobileMemberDashboard {
    constructor() {
        this.clubId = null;
        this.joinCode = null;
        this.currentSection = 'dashboard';
        this.data = {
            posts: [],
            assignments: [],
            meetings: [],
            projects: [],
            resources: [],
            submissions: []
        };

        this.init();
    }

    init() {
        console.log('Initializing mobile member dashboard...');

        this.showLoadingScreen();
        this.extractClubData();
        this.setupEventListeners();
        this.loadInitialData();
        this.hideLoadingScreen();
    }

    extractClubData() {
        const dashboard = document.getElementById('mobileDashboard');
        if (dashboard) {
            this.clubId = dashboard.dataset.clubId;
            this.joinCode = dashboard.dataset.joinCode;
        }
    }

    showLoadingScreen() {
        const loadingScreen = document.getElementById('mobileLoadingScreen');
        const dashboard = document.getElementById('mobileDashboard');

        if (loadingScreen && dashboard) {
            loadingScreen.style.display = 'flex';
            dashboard.style.display = 'none';
            document.body.classList.add('mobile-dashboard-active');
        }
    }

    hideLoadingScreen() {
        const loadingScreen = document.getElementById('mobileLoadingScreen');
        const dashboard = document.getElementById('mobileDashboard');

        if (loadingScreen && dashboard) {
            loadingScreen.style.opacity = '0';
            setTimeout(() => {
                loadingScreen.style.display = 'none';
                dashboard.style.display = 'flex';
            }, 300);
        }
    }

    setupEventListeners() {
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();
                const section = tab.dataset.section;
                this.openTab(section);
            });
        });
    }

    openTab(sectionName) {
        console.log('Opening member tab:', sectionName);

        if (['schedule', 'resources', 'pizza'].includes(sectionName)) {
            this.openDetailSection(sectionName);
            return;
        }

        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.remove('active');
        });

        const activeTab = document.querySelector(`.nav-tab[data-section="${sectionName}"]`);
        if (activeTab) {
            activeTab.classList.add('active');
        }

        document.querySelectorAll('.mobile-section').forEach(section => {
            section.classList.remove('active');
        });

        const targetSection = document.getElementById(`${sectionName}Section`);
        if (targetSection) {
            targetSection.classList.add('active');
            this.currentSection = sectionName;
            this.loadSectionData(sectionName);
        }
    }

    openDetailSection(sectionName) {
        const detailSection = document.getElementById(`${sectionName}Detail`);
        if (detailSection) {
            document.body.classList.add('detail-section-open');
            
            detailSection.style.display = 'flex';
            detailSection.style.transform = 'translateX(100%)';
            detailSection.style.transition = 'transform 0.2s ease';
            detailSection.classList.add('active');

            setTimeout(() => {
                detailSection.style.transform = 'translateX(0)';
            }, 10);

            this.loadSectionData(sectionName);
        }
    }

    closeDetailSection() {
        const activeDetail = document.querySelector('.detail-section.active, .detail-section[style*="flex"]');
        if (activeDetail) {
            activeDetail.style.transform = 'translateX(100%)';
            activeDetail.classList.remove('active');
            
            setTimeout(() => {
                activeDetail.style.display = 'none';
                document.body.classList.remove('detail-section-open');
            }, 200);
        }
    }

    async loadInitialData() {
        await this.loadAllData();
        this.updateStats();
    }

    async loadAllData() {
        try {
            const promises = [
                this.fetchData('posts'),
                this.fetchData('assignments'),
                this.fetchData('meetings'),
                this.fetchData('resources')
            ];

            await Promise.all(promises);
        } catch (error) {
            console.error('Error loading data:', error);
        }
    }

    loadSectionData(sectionName) {
        switch (sectionName) {
            case 'stream':
                this.loadPosts();
                break;
            case 'assignments':
                this.loadAssignments();
                break;
            case 'projects':
                this.loadMyProjects();
                break;
            case 'schedule':
                this.loadMeetings();
                break;
            case 'resources':
                this.loadResources();
                break;
            case 'pizza':
                this.loadMySubmissions();
                break;
        }
    }

    async fetchData(endpoint) {
        try {
            const response = await fetch(`/api/clubs/${this.clubId}/${endpoint}`);
            if (response.ok) {
                const data = await response.json();
                let arrayData = Array.isArray(data) ? data : (data.items || data.data || data[endpoint] || data.results || []);
                this.data[endpoint] = arrayData;
                return arrayData;
            }
        } catch (error) {
            console.error(`Error fetching ${endpoint}:`, error);
            throw error;
        }
    }

    async loadPosts() {
        const container = document.getElementById('mobilePostsList');
        if (!container) return;

        try {
            const posts = await this.fetchData('posts');
            
            if (!Array.isArray(posts) || posts.length === 0) {
                container.innerHTML = this.getEmptyState('stream', 'No announcements yet', 'Your club leaders will post updates here!');
            } else {
                container.innerHTML = posts.map(post => this.renderPost(post)).join('');
            }
        } catch (error) {
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading posts', 'Please try again later');
        }
    }

    async loadAssignments() {
        const container = document.getElementById('mobileAssignmentsList');
        if (!container) return;

        try {
            const assignments = await this.fetchData('assignments');
            
            if (!Array.isArray(assignments) || assignments.length === 0) {
                container.innerHTML = this.getEmptyState('tasks', 'No assignments yet', 'Your leaders will assign coding challenges soon!');
            } else {
                container.innerHTML = assignments.map(assignment => this.renderAssignment(assignment)).join('');
            }
        } catch (error) {
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading assignments', 'Please try again later');
        }
    }

    async loadMeetings() {
        const container = document.getElementById('mobileMeetingsList');
        if (!container) return;

        try {
            const meetings = await this.fetchData('meetings');
            
            if (!Array.isArray(meetings) || meetings.length === 0) {
                container.innerHTML = this.getEmptyState('calendar-times', 'No events scheduled', 'Check back for upcoming club events!');
            } else {
                container.innerHTML = meetings.map(meeting => this.renderMeeting(meeting)).join('');
            }
        } catch (error) {
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading meetings', 'Please try again later');
        }
    }

    async loadMyProjects() {
        const container = document.getElementById('mobileMyHackatimeProjectsList');
        if (!container) return;

        try {
            const response = await fetch(`/api/hackatime/projects/${window.currentUserId || ''}`);
            const data = await response.json();
            
            if (data.error) {
                container.innerHTML = this.getEmptyState('exclamation-triangle', 'Unable to load projects', data.error);
                return;
            }
            
            if (data.projects && data.projects.length > 0) {
                const projectsHtml = data.projects.map(project => this.renderHackatimeProject(project)).join('');
                container.innerHTML = projectsHtml;
            } else {
                container.innerHTML = this.getEmptyState('clock', 'No projects found', 'You haven\'t logged any coding time yet');
            }
        } catch (error) {
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading projects', 'Failed to fetch data');
        }
    }

    async loadResources() {
        const container = document.getElementById('mobileResourcesList');
        if (!container) return;

        try {
            const resources = await this.fetchData('resources');
            
            if (!Array.isArray(resources) || resources.length === 0) {
                container.innerHTML = this.getEmptyState('book', 'No resources yet', 'Your club leaders will share helpful resources here!');
            } else {
                container.innerHTML = resources.map(resource => this.renderResource(resource)).join('');
            }
        } catch (error) {
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading resources', 'Please try again later');
        }
    }

    async loadMySubmissions() {
        const container = document.getElementById('mobileMySubmissionsList');
        if (!container) return;

        // For now, show empty state - this would connect to actual submission API
        container.innerHTML = this.getEmptyState('hand-holding-usd', 'No submissions yet', 'Submit your first project to get started!');
    }

    renderPost(post) {
        const authorName = post.author_name || post.author || 'Unknown';
        const content = post.content || 'No content';
        const createdAt = post.created_at || new Date().toISOString();
        
        return `
            <div class="mobile-card" style="margin-bottom: 1rem;">
                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem;">
                    <div class="member-avatar" style="width: 35px; height: 35px; font-size: 0.8rem;">
                        ${authorName.charAt(0).toUpperCase()}
                    </div>
                    <div>
                        <div style="font-weight: 600; color: #1a202c; font-size: 0.9rem;">${authorName}</div>
                        <div style="font-size: 0.75rem; color: #6b7280;">${this.timeAgo(createdAt)}</div>
                    </div>
                </div>
                <p style="margin: 0; color: #4a5568; line-height: 1.4;">${content}</p>
            </div>
        `;
    }

    renderAssignment(assignment) {
        const title = assignment.title || 'Untitled Assignment';
        const description = assignment.description || 'No description available';
        const dueDate = assignment.due_date ? new Date(assignment.due_date) : null;
        const isOverdue = dueDate && dueDate < new Date();

        return `
            <div class="mobile-card" style="margin-bottom: 1rem; ${isOverdue ? 'border-left: 4px solid #ef4444;' : ''}">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
                    <h4 style="margin: 0; color: #1a202c; font-size: 1rem;">${title}</h4>
                    ${dueDate ? `<span style="font-size: 0.75rem; color: ${isOverdue ? '#ef4444' : '#6b7280'}; white-space: nowrap;">${this.formatDate(dueDate)}</span>` : ''}
                </div>
                <p style="margin: 0; color: #6b7280; font-size: 0.875rem; line-height: 1.4;">${description.length > 100 ? description.substring(0, 100) + '...' : description}</p>
                ${isOverdue ? '<div style="margin-top: 0.5rem; color: #ef4444; font-size: 0.75rem; font-weight: 600;"><i class="fas fa-exclamation-triangle"></i> Overdue</div>' : ''}
            </div>
        `;
    }

    renderMeeting(meeting) {
        const title = meeting.title || 'Untitled Meeting';
        const description = meeting.description || '';
        const location = meeting.location || '';
        const link = meeting.meeting_link || '';
        const datetime = meeting.meeting_date || new Date().toISOString();
        const meetingDate = new Date(datetime);

        return `
            <div class="mobile-card" style="margin-bottom: 1rem;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
                    <h4 style="margin: 0; color: #1a202c; font-size: 1rem;">${title}</h4>
                    <span style="font-size: 0.75rem; color: #6b7280; white-space: nowrap;">
                        ${this.formatDateTime(meetingDate)}
                    </span>
                </div>
                ${description ? `<p style="margin: 0 0 0.5rem 0; color: #6b7280; font-size: 0.875rem;">${description}</p>` : ''}
                ${location ? `<div style="font-size: 0.75rem; color: #6b7280;"><i class="fas fa-map-marker-alt"></i> ${location}</div>` : ''}
                ${link ? `<div style="margin-top: 0.5rem;"><a href="${link}" target="_blank" style="color: #ec3750; font-size: 0.75rem; text-decoration: none;"><i class="fas fa-external-link-alt"></i> Join Meeting</a></div>` : ''}
            </div>
        `;
    }

    renderResource(resource) {
        const title = resource.title || 'Untitled Resource';
        const description = resource.description || '';
        const url = resource.url || '#';
        const icon = resource.icon || 'link';
        
        return `
            <div class="mobile-card" style="margin-bottom: 1rem;">
                <div style="display: flex; align-items: center; gap: 0.75rem;">
                    <div style="width: 35px; height: 35px; background: rgba(236, 55, 80, 0.1); color: #ec3750; border-radius: 8px; display: flex; align-items: center; justify-content: center;">
                        <i class="fas fa-${icon}"></i>
                    </div>
                    <div style="flex: 1;">
                        <h4 style="margin: 0 0 0.25rem 0; color: #1a202c; font-size: 0.9rem;">${title}</h4>
                        ${description ? `<p style="margin: 0 0 0.5rem 0; color: #6b7280; font-size: 0.8rem;">${description}</p>` : ''}
                        <a href="${url}" target="_blank" style="color: #ec3750; font-size: 0.75rem; text-decoration: none;">
                            <i class="fas fa-external-link-alt"></i> Visit Resource
                        </a>
                    </div>
                </div>
            </div>
        `;
    }

    renderHackatimeProject(project) {
        return `
            <div class="mobile-card" style="margin-bottom: 1rem;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
                    <h4 style="margin: 0; color: #1a202c; font-size: 1rem;">
                        <i class="fas fa-code"></i> ${project.name}
                    </h4>
                    <span style="background: #10b981; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600;">${project.formatted_time}</span>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.875rem; color: #6b7280;">
                    <span style="display: flex; align-items: center; gap: 0.25rem;">
                        <i class="fas fa-clock"></i> ${project.total_seconds.toLocaleString()} seconds
                    </span>
                    ${project.percent ? `<span style="display: flex; align-items: center; gap: 0.25rem;"><i class="fas fa-chart-pie"></i> ${project.percent.toFixed(1)}%</span>` : ''}
                </div>
            </div>
        `;
    }

    updateStats() {
        const counters = {
            'mobileMembersAssignmentsCount': this.data.assignments?.length || 0,
            'mobileMemberProjectsCount': 0, // Will be updated by loadMyProjects
            'mobileMemberEventsCount': this.data.meetings?.length || 0,
            'mobileMemberSubmissionsCount': 0 // Will be updated when submissions are loaded
        };

        Object.entries(counters).forEach(([id, count]) => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = count;
            }
        });
    }

    getEmptyState(icon, title, description) {
        return `
            <div class="empty-state-mobile">
                <i class="fas fa-${icon}"></i>
                <h3>${title}</h3>
                <p>${description}</p>
            </div>
        `;
    }

    timeAgo(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const seconds = Math.floor((now - date) / 1000);

        const intervals = {
            year: 31536000,
            month: 2592000,
            week: 604800,
            day: 86400,
            hour: 3600,
            minute: 60
        };

        for (const [unit, secondsInUnit] of Object.entries(intervals)) {
            const interval = Math.floor(seconds / secondsInUnit);
            if (interval >= 1) {
                return `${interval} ${unit}${interval !== 1 ? 's' : ''} ago`;
            }
        }

        return 'Just now';
    }

    formatDate(date) {
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric'
        });
    }

    formatDateTime(date) {
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: 'numeric',
            minute: '2-digit'
        });
    }
}

// Global instance
let mobileMemberDashboard;

// Global functions for compatibility
function openTab(sectionName) {
    if (mobileMemberDashboard) {
        mobileMemberDashboard.openTab(sectionName);
    }
}

function closeDetailSection() {
    if (mobileMemberDashboard) {
        mobileMemberDashboard.closeDetailSection();
    }
}

function openPizzaGrantModal() {
    const modal = document.getElementById('pizzaGrantModal');
    if (modal) {
        modal.style.display = 'block';
    }
}

function closeMobileModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
    }
}

