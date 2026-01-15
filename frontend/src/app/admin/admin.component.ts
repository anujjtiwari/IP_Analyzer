import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { AdminHeaderComponent } from '../admin-header/admin-header.component';
import { FormService } from '../form.service';
import { Router } from '@angular/router';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { FormsModule } from '@angular/forms';
import {
	faTrash,
	faLock,
	faLockOpen,
	faUser,
	faUserGear,
	faArrowsRotate,
} from '@fortawesome/free-solid-svg-icons';

import { FaIconLibrary } from '@fortawesome/angular-fontawesome';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import { LoaderComponent } from '../loader/loader.component';

@Component({
	selector: 'app-admin',
	standalone: true,
	imports: [AdminHeaderComponent, CommonModule, MatSnackBarModule, FormsModule, FontAwesomeModule, LoaderComponent],
	templateUrl: './admin.component.html',
	styleUrl: './admin.component.css',
})
export class AdminComponent implements OnInit {
	userList: any[] = [];
	filteredUsers: any[] = [];
	searchId: string = '';
	searchName: string = '';
	searchEmail: string = '';
	isAdminFilter: string = 'all'; // 'all', 'true', 'false'
	isLockedFilter: string = 'all'; // 'all', 'true', 'false'
	isLoading: boolean = false;

	constructor(
		private formService: FormService,
		private router: Router,
		private snackBar: MatSnackBar,
		library: FaIconLibrary
	) { 
		library.addIcons(faTrash, faLock, faLockOpen, faUser, faUser, faUserGear, faArrowsRotate);
	}

	ngOnInit() {
		this.formService.get_user_list().subscribe({
			next: (response) => {
				this.userList = JSON.parse(response)['user_list'];
				this.filteredUsers = [...this.userList];
			},
			error: (error) => {
				this.snackBar.open('Unauthorized!', 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});

				this.router.navigate(['/home']);
			},
			complete: () => {
				console.log('User Name List Handling Completed.');
			},
		});
	}

	filterUsers(): void {
		this.isLoading = true;
		this.filteredUsers = this.userList.filter((user) => {
			return (
				(this.searchId === '' || user._id.includes(this.searchId)) &&
				(this.searchName === '' ||
					user.name.toLowerCase().includes(this.searchName.toLowerCase())) &&
				(this.searchEmail === '' ||
					user.email.toLowerCase().includes(this.searchEmail.toLowerCase())) &&
				(this.isAdminFilter === 'all' ||
					user.is_admin.toString() === this.isAdminFilter) &&
				(this.isLockedFilter === 'all' ||
					user.is_locked.toString() === this.isLockedFilter)
			);
		});
		this.isLoading = false;
	}

	deleteUser(userId:string): void {
		this.isLoading = true;
		this.formService.delete_user(userId).subscribe({
			next: (response) => {
				this.snackBar.open(JSON.parse(response)["message"], 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});

				this.userList.filter((user) => {
					return (user._id != userId);
				})

				this.filteredUsers.filter((user) => {
					return (user._id != userId);
				})

				this.refreshTable();
				this.isLoading = false;
			},
			error: (error) => {
				this.snackBar.open(JSON.parse(error['error'])['message'], 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});
				this.isLoading = false;
			},
			complete: () => {
				console.log("User Account Deletion Handling Complete.")
			}
		})
	}

	lockUser(userId:string): void {
		this.isLoading = true;
		this.formService.lock_user(userId).subscribe({
			next: (response) => {
				this.snackBar.open(JSON.parse(response)["message"], 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});

				const user_to_update = this.userList.find((user) => user._id === userId);
				if (user_to_update) {
					user_to_update["is_locked"] = true;
				}

				const filtered_user_to_update = this.filteredUsers.find((user) => user._id === userId);
				if (filtered_user_to_update) {
					filtered_user_to_update["is_locked"] = true;
				}
				this.isLoading = false;
			},
			error: (error) => {
				this.snackBar.open(JSON.parse(error['error'])['message'], 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});
				this.isLoading = false;
			},
			complete: () => {
				console.log("User Account Locking Handling Complete.")
			}
		})
	}

	unLockUser(userId:string): void {
		this.isLoading = true;
		this.formService.unlock_user(userId).subscribe({
			next: (response) => {
				this.snackBar.open(JSON.parse(response)["message"], 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});

				const user_to_update = this.userList.find((user) => user._id === userId);
				if (user_to_update) {
					user_to_update["is_locked"] = false;
				}

				const filtered_user_to_update = this.filteredUsers.find((user) => user._id === userId);
				if (filtered_user_to_update) {
					filtered_user_to_update["is_locked"] = false;
				}
				this.isLoading = false;
			},
			error: (error) => {
				this.snackBar.open(JSON.parse(error['error'])['message'], 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});
				this.isLoading = false;
			},
			complete: () => {
				console.log("User Account Unlocking Handling Complete.")
			}
		})
	}

	makeAdmin(userId:string): void {
		this.isLoading = true;
		this.formService.make_admin(userId).subscribe({
			next: (response) => {
				this.snackBar.open(JSON.parse(response)["message"], 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});

				const user_to_update = this.userList.find((user) => user._id === userId);
				if (user_to_update) {
					user_to_update["is_admin"] = true;
				}

				const filtered_user_to_update = this.filteredUsers.find((user) => user._id === userId);
				if (filtered_user_to_update) {
					filtered_user_to_update["is_admin"] = true;
				}
				this.isLoading = false;
			},
			error: (error) => {
				this.snackBar.open(JSON.parse(error['error'])['message'], 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});
				this.isLoading = false;
			},
			complete: () => {
				console.log("User Account Upgrade Handling Complete.")
			}
		})
	}

	revokeAdmin(userId:string): void {
		this.isLoading = true;
		this.formService.revoke_admin(userId).subscribe({
			next: (response) => {
				this.snackBar.open(JSON.parse(response)["message"], 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});

				const user_to_update = this.userList.find((user) => user._id === userId);
				if (user_to_update) {
					user_to_update["is_admin"] = false;
				}

				const filtered_user_to_update = this.filteredUsers.find((user) => user._id === userId);
				if (filtered_user_to_update) {
					filtered_user_to_update["is_admin"] = false;
				}
				this.isLoading = false;
			},
			error: (error) => {
				this.snackBar.open(JSON.parse(error['error'])['message'], 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});
				this.isLoading = false;
			},
			complete: () => {
				console.log("User Account Downgrade Handling Complete.")
			}
		})
	}

	refreshTable(): void {
		this.isLoading = true;
		this.formService.get_user_list().subscribe({
			next: (response) => {
				this.userList = JSON.parse(response)['user_list'];
				this.filteredUsers = [...this.userList];
				this.isLoading = false;
			},
			error: (error) => {
				this.snackBar.open('Unauthorized!', 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});
				this.isLoading = false;
				this.router.navigate(['/home']);
			},
			complete: () => {
				console.log('User Name List Handling Completed.');
			},
		});
	}

}
