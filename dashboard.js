// Global variables
let userLocation = null;
let userCity = 'Dhaka';
let userCoordinates = null;

function checkAuth() {
    const isLoggedIn = localStorage.getItem('healthmate_loggedIn');
    const userEmail = localStorage.getItem('healthmate_user');
    
    if (!isLoggedIn || !userEmail) {
        window.location.href = 'login.html';
        return;
    }
    
    loadUserData(userEmail);
}

function loadUserData(email) {
    document.getElementById('profileName').textContent = email.split('@')[0];
    document.getElementById('profileEmail').textContent = email;
    document.getElementById('profileAge').textContent = '25';
    document.getElementById('userName').textContent = email.split('@')[0] + ' (You)';
}

function showSection(sectionId) {
    document.querySelectorAll('.section').forEach(section => {
        section.classList.add('hidden');
    });
    document.getElementById(sectionId).classList.remove('hidden');
    
    // Auto-detect location when AI Health Insights section is opened
    if (sectionId === 'aiHealthInsights') {
        setTimeout(() => {
            detectLocation();
        }, 500);
    }
}

// Location Detection Functions
function detectLocation() {
    const locationStatus = document.getElementById('locationStatus');
    const locationDetails = document.getElementById('locationDetails');
    
    locationStatus.textContent = 'Detecting your location...';
    locationDetails.classList.add('hidden');
    
    if (!navigator.geolocation) {
        locationStatus.textContent = 'Geolocation is not supported by this browser. Using default location (Dhaka).';
        userCity = 'Dhaka';
        updateLocationDisplay();
        return;
    }

    navigator.geolocation.getCurrentPosition(
        async (position) => {
            const latitude = position.coords.latitude;
            const longitude = position.coords.longitude;
            userCoordinates = { latitude, longitude };
            
            locationStatus.textContent = 'Location detected! Getting address...';
            
            try {
                // For demo purposes, we'll use Dhaka as default
                userCity = 'Dhaka';
                userLocation = 'Dhaka, Bangladesh';
                
                locationStatus.textContent = `Location detected successfully!`;
                updateLocationDisplay();
                locationDetails.classList.remove('hidden');
                
            } catch (error) {
                console.error('Error getting address:', error);
                locationStatus.textContent = 'Location detected but could not get address. Using default search area.';
                userCity = 'Dhaka';
                updateLocationDisplay();
                locationDetails.classList.remove('hidden');
            }
        },
        (error) => {
            console.error('Error getting location:', error);
            let errorMessage = 'Unable to detect your location. ';
            
            switch (error.code) {
                case error.PERMISSION_DENIED:
                    errorMessage += 'Location access was denied. Using default location (Dhaka).';
                    break;
                case error.POSITION_UNAVAILABLE:
                    errorMessage += 'Location information is unavailable. Using default location (Dhaka).';
                    break;
                case error.TIMEOUT:
                    errorMessage += 'Location request timed out. Using default location (Dhaka).';
                    break;
                default:
                    errorMessage += 'An unknown error occurred. Using default location (Dhaka).';
                    break;
            }
            
            locationStatus.textContent = errorMessage;
            userCity = 'Dhaka';
            updateLocationDisplay();
            locationDetails.classList.remove('hidden');
        },
        {
            enableHighAccuracy: true,
            timeout: 10000,
            maximumAge: 60000
        }
    );
}

function updateLocationDisplay() {
    document.getElementById('detectedLocation').textContent = userLocation || userCity;
    document.getElementById('searchArea').textContent = userCity;
    document.getElementById('distanceFilter').textContent = 'Within 5 km radius';
}

// Enhanced Doctor Functions with Backend Integration
async function fetchDoctorsFromBackend(doctorType) {
    try {
        const response = await fetch(`/api/doctors?specialization=${encodeURIComponent(doctorType)}&location=${encodeURIComponent(userCity)}`);
        const data = await response.json();
        
        if (data.success && data.doctors) {
            console.log(`✅ Found ${data.doctors.length} doctors from backend`);
            return data.doctors;
        } else {
            throw new Error(data.message || 'Failed to fetch doctors');
        }
    } catch (error) {
        console.error('❌ Backend fetch failed:', error);
        // Fallback to local sample data
        return generateSampleDoctors(doctorType);
    }
}

async function viewDoctorProfile(name, specialization) {
    try {
        // Try to get real profile from backend
        const response = await fetch(`/api/doctor-profile?name=${encodeURIComponent(name)}&specialization=${encodeURIComponent(specialization)}`);
        const data = await response.json();
        
        if (data.success && data.profile) {
            showDoctorProfileModal(data.profile);
        } else {
            // Fallback to demo profile
            showDemoProfile(name, specialization);
        }
    } catch (error) {
        console.error('Error fetching doctor profile:', error);
        showDemoProfile(name, specialization);
    }
}

function showDoctorProfileModal(profile) {
    const modalHtml = `
        <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl p-6 modal-pop-in max-h-[90vh] overflow-y-auto">
                <div class="flex justify-between items-start mb-4">
                    <h2 class="text-2xl font-bold text-blue-600">Doctor Profile</h2>
                    <button onclick="closeModal()" class="text-gray-500 hover:text-gray-700 text-2xl">&times;</button>
                </div>
                
                <div class="grid md:grid-cols-3 gap-6">
                    <div class="md:col-span-2">
                        <div class="flex items-center gap-4 mb-4">
                            <div class="text-4xl">👨‍⚕️</div>
                            <div>
                                <h3 class="text-xl font-bold text-gray-800">${profile.name}</h3>
                                <p class="text-green-600 font-semibold">${profile.specialization}</p>
                                <div class="flex items-center gap-2 mt-1">
                                    <span class="text-yellow-500">⭐ ${profile.rating}</span>
                                    <span class="text-gray-500 text-sm">(${profile.review_count || '50+'} reviews)</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="space-y-3 text-sm">
                            <p><strong>🎓 Education:</strong> ${profile.education}</p>
                            <p><strong>📅 Experience:</strong> ${profile.experience}</p>
                            <p><strong>🏥 Hospital:</strong> ${profile.hospital}</p>
                            <p><strong>💰 Consultation Fee:</strong> ${profile.consultation_fee}</p>
                            <p><strong>🗣️ Languages:</strong> ${profile.languages}</p>
                            <p><strong>⏰ Availability:</strong> ${profile.availability}</p>
                            <p><strong>📞 Contact:</strong> ${profile.contact}</p>
                            <p><strong>📍 Address:</strong> ${profile.address}</p>
                        </div>
                        
                        ${profile.expertise ? `
                        <div class="mt-4">
                            <h4 class="font-semibold text-gray-700 mb-2">Areas of Expertise:</h4>
                            <div class="flex flex-wrap gap-2">
                                ${profile.expertise.map(exp => `<span class="bg-blue-100 text-blue-800 px-3 py-1 rounded-full text-sm">${exp}</span>`).join('')}
                            </div>
                        </div>
                        ` : ''}
                    </div>
                    
                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-semibold text-gray-700 mb-3">Book Appointment</h4>
                        <form id="appointmentForm" onsubmit="submitAppointment(event, '${profile.name.replace(/'/g, "\\'")}', '${profile.specialization}')">
                            <div class="space-y-3">
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-1">Preferred Date</label>
                                    <input type="date" required class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-1">Preferred Time</label>
                                    <select required class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm">
                                        <option value="">Select Time</option>
                                        <option>Morning (9AM-12PM)</option>
                                        <option>Afternoon (2PM-5PM)</option>
                                        <option>Evening (6PM-8PM)</option>
                                    </select>
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-1">Your Name</label>
                                    <input type="text" required class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" value="${localStorage.getItem('healthmate_user')?.split('@')[0] || ''}">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-1">Your Email</label>
                                    <input type="email" required class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" value="${localStorage.getItem('healthmate_user') || ''}">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-1">Notes (Optional)</label>
                                    <textarea class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" rows="2" placeholder="Any specific concerns..."></textarea>
                                </div>
                                <button type="submit" class="w-full bg-green-500 text-white py-2 rounded-lg font-semibold hover:bg-green-600 transition-colors">
                                    Book Appointment
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    const modalContainer = document.createElement('div');
    modalContainer.innerHTML = modalHtml;
    modalContainer.id = 'doctorProfileModal';
    document.body.appendChild(modalContainer);
}

async function submitAppointment(event, doctorName, specialization) {
    event.preventDefault();
    
    const form = event.target;
    const formData = new FormData(form);
    
    const appointmentData = {
        doctorName: doctorName,
        specialization: specialization,
        patientName: formData.get('name') || form.querySelector('input[type="text"]').value,
        patientEmail: formData.get('email') || form.querySelector('input[type="email"]').value,
        preferredDate: formData.get('date') || form.querySelector('input[type="date"]').value,
        preferredTime: formData.get('time') || form.querySelector('select').value,
        notes: formData.get('notes') || form.querySelector('textarea').value
    };
    
    try {
        const response = await fetch('/api/book-appointment', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(appointmentData)
        });
        
        const result = await response.json();
        
        if (result.success) {
            alert('✅ ' + result.message + '\nAppointment ID: ' + result.appointment_id);
            closeModal();
        } else {
            alert('❌ ' + result.message);
        }
    } catch (error) {
        console.error('Error booking appointment:', error);
        alert('❌ Failed to book appointment. Please try again.');
    }
}

function closeModal() {
    const modal = document.getElementById('doctorProfileModal');
    if (modal) {
        modal.remove();
    }
}

// Fallback functions
function showDemoProfile(name, specialization) {
    const modalHtml = `
        <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div class="bg-white rounded-xl shadow-2xl w-full max-w-md p-6 modal-pop-in">
                <div class="text-center mb-4">
                    <div class="text-4xl mb-2">👨‍⚕️</div>
                    <h2 class="text-2xl font-bold text-blue-600">${name}</h2>
                    <p class="text-green-600 font-semibold">${specialization}</p>
                </div>
                
                <div class="space-y-3 text-sm">
                    <p><strong>🏥 Hospital:</strong> Multiple locations in ${userCity}</p>
                    <p><strong>📅 Experience:</strong> 10+ years</p>
                    <p><strong>🎓 Education:</strong> MBBS, MD, FCPS</p>
                    <p><strong>⭐ Rating:</strong> 4.7/5 (Based on patient reviews)</p>
                    <p><strong>🗣️ Languages:</strong> Bengali, English</p>
                    <p><strong>⏰ Availability:</strong> Mon-Sat, 9AM-5PM</p>
                </div>
                
                <div class="mt-6 p-3 bg-blue-50 rounded-lg">
                    <p class="text-xs text-blue-600 text-center">
                        <strong>Note:</strong> This is a demo profile. In production, this would show real data from healthcare providers.
                    </p>
                </div>
                
                <div class="flex justify-end gap-3 mt-6">
                    <button onclick="closeModal()" class="bg-slate-200 text-slate-700 px-4 py-2 rounded-lg hover:bg-slate-300">Close</button>
                    <button onclick="bookAppointment('${name.replace(/'/g, "\\'")}','${specialization}')" class="bg-green-500 text-white px-4 py-2 rounded-lg hover:bg-green-600">Book Appointment</button>
                </div>
            </div>
        </div>
    `;
    
    showModal(modalHtml, 'demoProfileModal');
}

function bookAppointment(name, specialization, hospital) {
    const modalHtml = `
        <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div class="bg-white rounded-xl shadow-2xl w-full max-w-md p-6 modal-pop-in">
                <h2 class="text-2xl font-bold text-green-600 mb-4">Book Appointment</h2>
                
                <div class="space-y-4">
                    <div class="p-3 bg-green-50 rounded-lg">
                        <p><strong>Doctor:</strong> ${name}</p>
                        <p><strong>Specialization:</strong> ${specialization}</p>
                        ${hospital ? `<p><strong>Hospital:</strong> ${hospital}</p>` : ''}
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-slate-700 mb-1">Preferred Date</label>
                        <input type="date" class="border border-slate-300 w-full p-2 rounded-lg">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-slate-700 mb-1">Preferred Time</label>
                        <select class="border border-slate-300 w-full p-2 rounded-lg">
                            <option>Morning (9AM-12PM)</option>
                            <option>Afternoon (2PM-5PM)</option>
                            <option>Evening (6PM-8PM)</option>
                        </select>
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-slate-700 mb-1">Phone Number</label>
                        <input type="tel" placeholder="+8801XXXXXXXXX" class="border border-slate-300 w-full p-2 rounded-lg">
                    </div>
                </div>
                
                <div class="mt-4 p-3 bg-yellow-50 rounded-lg">
                    <p class="text-xs text-yellow-700 text-center">
                        <strong>Demo Feature:</strong> This would integrate with healthcare providers' booking systems in production
                    </p>
                </div>
                
                <div class="flex justify-end gap-3 mt-6">
                    <button onclick="closeModal()" class="bg-slate-200 text-slate-700 px-4 py-2 rounded-lg hover:bg-slate-300">Cancel</button>
                    <button onclick="confirmAppointment()" class="bg-green-500 text-white px-4 py-2 rounded-lg hover:bg-green-600">Confirm Booking</button>
                </div>
            </div>
        </div>
    `;
    
    showModal(modalHtml, 'appointmentModal');
}

function showModal(html, id) {
    const modalContainer = document.createElement('div');
    modalContainer.innerHTML = html;
    modalContainer.id = id;
    document.body.appendChild(modalContainer);
}

function confirmAppointment() {
    alert('Appointment booking feature would be integrated with healthcare providers in production.');
    closeModal();
}

// Keep your existing modal functions (they should work with the dashboard.html)
function openFamilyModal() {
    document.getElementById('familyModal').classList.remove('hidden');
}

function closeFamilyModal() {
    document.getElementById('familyModal').classList.add('hidden');
}

function openReminderModal() {
    document.getElementById('reminderModal').classList.remove('hidden');
}

function closeReminderModal() {
    document.getElementById('reminderModal').classList.add('hidden');
}

function openReportModal() {
    document.getElementById('reportModal').classList.remove('hidden');
}

function closeReportModal() {
    document.getElementById('reportModal').classList.add('hidden');
}

function saveFamilyMember() {
    const name = document.getElementById('familyName').value;
    if (name) {
        const familyList = document.getElementById('familyList');
        const li = document.createElement('li');
        li.textContent = name;
        familyList.appendChild(li);
        closeFamilyModal();
        document.getElementById('familyName').value = '';
    }
}

function logout() {
    localStorage.removeItem('healthmate_user');
    localStorage.removeItem('healthmate_loggedIn');
    window.location.href = 'login.html';
}

document.addEventListener('DOMContentLoaded', function() {
    checkAuth();
    showSection('dashboard');
    
    // Initialize body hotspots if they exist
    if (typeof initHotspots === 'function') {
        setTimeout(initHotspots, 1000);
    }
});