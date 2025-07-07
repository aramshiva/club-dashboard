// Mobile Club Dashboard JavaScript


class MobileClubDashboard {
    constructor() {
        this.clubId = null;
        this.joinCode = null;
        this.isLeader = false;
        this.currentSection = 'dashboard';
        this.isLoading = true;
        this.loadingTimeout = null;
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
        console.log('Initializing mobile club dashboard...');

        // Show loading screen
        this.showLoadingScreen();

        // Get club data
        this.extractClubData();

        // Set up event listeners
        this.setupEventListeners();

        // Initialize PWA functionality
        this.initPWA();

        // Add enhanced interactions
        this.addRippleEffect();
        this.createActiveIndicator();

        // Load initial data
        this.loadInitialData();

        // Hide loading screen immediately after data loads
        this.hideLoadingScreen();
    }

    extractClubData() {
        const dashboard = document.getElementById('mobileDashboard');
        if (dashboard) {
            this.clubId = dashboard.dataset.clubId;
            this.joinCode = dashboard.dataset.joinCode;
            this.isLeader = window.clubData?.isLeader || false;

            console.log('Retrieved Club ID:', this.clubId);
            console.log('Retrieved Join Code:', this.joinCode);
            console.log('Is Leader:', this.isLeader);
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
                this.isLoading = false;

                // Trigger entrance animations
                this.triggerEntranceAnimations();
            }, 300);
        }
    }

    triggerEntranceAnimations() {
        // Immediate animations - no delays
        const statCards = document.querySelectorAll('.stat-card');
        statCards.forEach((card) => {
            card.style.animationDelay = '0s';
        });

        // Immediate animations - no delays
        const quickActions = document.querySelectorAll('.quick-action-btn');
        quickActions.forEach((button) => {
            button.style.animationDelay = '0s';
        });

        // Add scroll animations
        this.setupScrollAnimations();
    }

    addRippleEffect() {
        // Enhanced ripple effect for all interactive elements
        const selectors = [
            '.mobile-btn-primary',
            '.quick-action-btn',
            '.stat-card',
            '.mobile-card',
            '.nav-tab',
            '.action-btn',
            '.member-card'
        ];
        
        selectors.forEach(selector => {
            document.addEventListener('click', (e) => {
                const element = e.target.closest(selector);
                if (!element) return;
                
                this.createRipple(element, e);
            });
        });
    }

    createRipple(element, event) {
        const ripple = document.createElement('span');
        const rect = element.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height) * 1.5;
        const x = event.clientX - rect.left - size / 2;
        const y = event.clientY - rect.top - size / 2;
        
        ripple.className = 'ripple-effect';
        ripple.style.cssText = `
            position: absolute;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.3);
            transform: scale(0);
            animation: superRipple 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            pointer-events: none;
            z-index: 1000;
        `;
        
        element.style.position = 'relative';
        element.style.overflow = 'hidden';
        element.appendChild(ripple);
        
        setTimeout(() => {
            if (ripple.parentNode) {
                ripple.remove();
            }
        }, 400);
    }

    setupScrollAnimations() {
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                } else {
                    entry.target.style.opacity = '0';
                    entry.target.style.transform = 'translateY(20px)';
                }
            });
        }, observerOptions);

        // Observe cards for scroll animations
        const animatedElements = document.querySelectorAll('.mobile-card');
        animatedElements.forEach(el => {
            el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
            observer.observe(el);
        });
    }

    setupEventListeners() {
        // Navigation tabs
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();
                const section = tab.dataset.section;
                this.openTab(section);
            });
        });

        // Touch gestures for better mobile experience
        this.setupTouchGestures();

        // Form submissions
        this.setupFormHandlers();

        // Pull to refresh
        this.setupPullToRefresh();
    }

    setupTouchGestures() {
        let startY = 0;
        let startX = 0;
        const content = document.getElementById('mobileContent');

        if (content) {
            content.addEventListener('touchstart', (e) => {
                startY = e.touches[0].clientY;
                startX = e.touches[0].clientX;
            }, { passive: true });

            content.addEventListener('touchmove', (e) => {
                // Prevent rubber band effect on iOS
                if (content.scrollTop === 0 && e.touches[0].clientY > startY) {
                    e.preventDefault();
                }
            }, { passive: false });
        }
    }

    setupFormHandlers() {
        // Mobile club settings form
        const settingsForm = document.getElementById('mobileClubSettingsForm');
        if (settingsForm) {
            settingsForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.saveClubSettings();
            });
        }
    }

    setupPullToRefresh() {
        let startY = 0;
        let pullDistance = 0;
        const content = document.getElementById('mobileContent');
        const threshold = 80;

        if (content) {
            content.addEventListener('touchstart', (e) => {
                if (content.scrollTop === 0) {
                    startY = e.touches[0].clientY;
                }
            }, { passive: true });

            content.addEventListener('touchmove', (e) => {
                if (content.scrollTop === 0 && startY > 0) {
                    pullDistance = e.touches[0].clientY - startY;
                    if (pullDistance > 0 && pullDistance < threshold * 2) {
                        content.style.transform = `translateY(${pullDistance * 0.5}px)`;
                        content.style.opacity = `${1 - (pullDistance / threshold) * 0.3}`;
                    }
                }
            }, { passive: true });

            content.addEventListener('touchend', () => {
                if (pullDistance > threshold) {
                    this.refreshData();
                }
                content.style.transform = '';
                content.style.opacity = '';
                startY = 0;
                pullDistance = 0;
            }, { passive: true });
        }
    }

    async refreshData() {
        await this.loadAllData();
    }

    openTab(sectionName) {
        if (this.isLoading) return;

        console.log('Opening tab:', sectionName);

        // Handle detail sections
        if (['schedule', 'resources', 'pizza', 'shop', 'ysws', 'settings'].includes(sectionName)) {
            this.openDetailSection(sectionName);
            return;
        }

        // Update active tab with sliding indicator
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.remove('active');
        });

        const activeTab = document.querySelector(`.nav-tab[data-section="${sectionName}"]`);
        if (activeTab) {
            activeTab.classList.add('active');
            this.updateActiveIndicator(activeTab);
        }

        // Fast section switching without complex animations
        document.querySelectorAll('.mobile-section').forEach(section => {
            section.classList.remove('active');
        });

        const targetSection = document.getElementById(`${sectionName}Section`);
        if (targetSection) {
            targetSection.classList.add('active');
            this.currentSection = sectionName;

            // Load section data if needed
            this.loadSectionData(sectionName);
        }
    }

    updateActiveIndicator(activeTab) {
        const indicator = document.querySelector('.nav-active-indicator') || this.createActiveIndicator();
        const tabRect = activeTab.getBoundingClientRect();
        const navRect = document.querySelector('.nav-tabs').getBoundingClientRect();
        
        const left = tabRect.left - navRect.left;
        const width = tabRect.width;
        
        indicator.style.transform = `translateX(${left}px)`;
        indicator.style.width = `${width}px`;
    }

    createActiveIndicator() {
        const indicator = document.createElement('div');
        indicator.className = 'nav-active-indicator';
        document.querySelector('.nav-tabs').appendChild(indicator);
        return indicator;
    }

    openDetailSection(sectionName) {
        const detailSection = document.getElementById(`${sectionName}Detail`);
        if (detailSection) {
            // Add body class to hide header/nav
            document.body.classList.add('detail-section-open');
            
            detailSection.style.display = 'flex';
            detailSection.style.transform = 'translateX(100%)';
            detailSection.style.transition = 'transform 0.2s ease';
            detailSection.classList.add('active');

            setTimeout(() => {
                detailSection.style.transform = 'translateX(0)';
            }, 10);

            // Load section data
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
                // Remove body class to show header/nav again
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
                this.fetchData('projects')
            ];

            await Promise.all(promises);
        } catch (error) {
            console.error('Error loading data:', error);
            this.showToast('Error loading data', 'error');
        }
    }

    async loadSectionData(sectionName) {
        switch (sectionName) {
            case 'stream':
                await this.loadPosts();
                break;
            case 'assignments':
                await this.loadAssignments();
                break;
            case 'projects':
                await this.loadProjects();
                break;
            case 'schedule':
                await this.loadMeetings();
                break;
            case 'resources':
                await this.loadResources();
                break;
            case 'pizza':
                await this.loadSubmissions();
                break;
        }
    }

    async fetchData(endpoint) {
        try {
            const response = await fetch(`/api/clubs/${this.clubId}/${endpoint}`);
            if (response.ok) {
                const data = await response.json();
                console.log(`Fetched ${endpoint} data:`, data);
                
                // Handle different response formats
                let arrayData;
                if (Array.isArray(data)) {
                    arrayData = data;
                } else if (data && typeof data === 'object') {
                    // Try common array property names
                    arrayData = data.items || data.data || data[endpoint] || data.results || [];
                    
                    // If it's still not an array, wrap single object in array
                    if (!Array.isArray(arrayData)) {
                        arrayData = [data];
                    }
                } else {
                    arrayData = [];
                }
                
                this.data[endpoint] = arrayData;
                console.log(`Processed ${endpoint} data:`, arrayData);
                return arrayData;
            } else {
                console.error(`Failed to fetch ${endpoint}: ${response.status} ${response.statusText}`);
                throw new Error(`Failed to fetch ${endpoint}: ${response.status}`);
            }
        } catch (error) {
            console.error(`Error fetching ${endpoint}:`, error);
            throw error;
        }
    }

    async loadPosts() {
        const container = document.getElementById('mobilePostsList');
        if (!container) return;

        this.showSectionLoading(container, 'Loading posts...');

        try {
            const posts = await this.fetchData('posts');
            console.log('Loaded posts:', posts);

            if (!Array.isArray(posts) || posts.length === 0) {
                container.innerHTML = this.getEmptyState('stream', 'No posts yet', 'Be the first to share something!');
            } else {
                container.innerHTML = posts.map(post => this.renderPost(post)).join('');
            }
        } catch (error) {
            console.error('Error loading posts:', error);
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading posts', 'Please try again later');
        }
    }

    async loadAssignments() {
        const container = document.getElementById('mobileAssignmentsList');
        if (!container) return;

        this.showSectionLoading(container, 'Loading assignments...');

        try {
            const assignments = await this.fetchData('assignments');
            console.log('Loaded assignments:', assignments);

            if (!Array.isArray(assignments) || assignments.length === 0) {
                container.innerHTML = this.getEmptyState('tasks', 'No assignments yet', 'Check back for new coding challenges!');
            } else {
                container.innerHTML = assignments.map(assignment => this.renderAssignment(assignment)).join('');
            }
        } catch (error) {
            console.error('Error loading assignments:', error);
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading assignments', 'Please try again later');
        }
    }

    async loadMeetings() {
        const container = document.getElementById('mobileMeetingsList');
        if (!container) return;

        this.showSectionLoading(container, 'Loading meetings...');

        try {
            const meetings = await this.fetchData('meetings');
            console.log('Loaded meetings:', meetings);

            if (!Array.isArray(meetings) || meetings.length === 0) {
                container.innerHTML = this.getEmptyState('calendar-times', 'No meetings scheduled', 'Check back for upcoming events!');
            } else {
                container.innerHTML = meetings.map(meeting => this.renderMeeting(meeting)).join('');
            }
        } catch (error) {
            console.error('Error loading meetings:', error);
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading meetings', 'Please try again later');
        }
    }

    async loadProjects() {
        // Projects are handled differently - they show Hackatime integration
        const projects = await this.fetchData('projects');
        this.updateProjectsCount(projects);
    }

    async loadHackatimeProjects() {
        const memberId = document.getElementById('mobileHackatimeMemberSelect').value;
        const container = document.getElementById('mobileHackatimeProjectsList');
        
        if (!memberId || !container) {
            container.innerHTML = this.getEmptyState('user', 'Select a member', 'Choose a member to view their coding projects');
            return;
        }

        this.showSectionLoading(container, 'Loading Hackatime projects...');

        try {
            const response = await fetch(`/api/hackatime/projects/${memberId}`);
            const data = await response.json();
            
            if (data.error) {
                container.innerHTML = this.getEmptyState('exclamation-triangle', 'Unable to load projects', data.error);
                return;
            }
            
            if (data.projects && data.projects.length > 0) {
                const title = `<h4 style="margin-bottom: 1rem; color: #1a202c;">${data.username}'s Hackatime Projects</h4>`;
                const projectsHtml = data.projects.map(project => this.renderHackatimeProject(project)).join('');
                container.innerHTML = title + projectsHtml;
            } else {
                container.innerHTML = this.getEmptyState('clock', 'No projects found', `${data.username} hasn't logged any coding time yet on Hackatime`);
            }
        } catch (error) {
            console.error('Error loading Hackatime projects:', error);
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading projects', 'Failed to fetch Hackatime data. Please try again.');
        }
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
                    ${project.percent ? `<span style="display: flex; align-items: center; gap: 0.25rem;"><i class="fas fa-chart-pie"></i> ${project.percent.toFixed(1)}% of total time</span>` : ''}
                </div>
            </div>
        `;
    }

    async loadResources() {
        const container = document.getElementById('mobileResourcesList');
        if (!container) return;

        this.showSectionLoading(container, 'Loading resources...');

        try {
            const resources = await this.fetchData('resources');
            console.log('Loaded resources:', resources);

            if (!Array.isArray(resources) || resources.length === 0) {
                container.innerHTML = this.getEmptyState('book', 'No resources yet', 'Add helpful links and materials!');
            } else {
                container.innerHTML = resources.map(resource => this.renderResource(resource)).join('');
            }
        } catch (error) {
            console.error('Error loading resources:', error);
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading resources', 'Please try again later');
        }
    }

