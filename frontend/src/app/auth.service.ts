import { Injectable } from '@angular/core';

@Injectable({
	providedIn: 'root'
})
export class AuthService {
	// true for testing, should be false in production
	private isAuthenticated = true;
	private allowedToSetPassword = false;

	constructor() { }

	login() {
		// Simulate a login and set isAuthenticated to true
		this.isAuthenticated = true;
	}

	logout() {
		// Simulate a logout and set isAuthenticated to false
		this.isAuthenticated = false;
	}

	allowToSetPassword() {
		this.allowedToSetPassword = true;
	}

	passwordSet() {
		this.allowedToSetPassword = false;
	}

	isLoggedIn(): boolean {
		return this.isAuthenticated;
	}

	canSetPassword():boolean {
		return this.allowedToSetPassword;
	}
}
