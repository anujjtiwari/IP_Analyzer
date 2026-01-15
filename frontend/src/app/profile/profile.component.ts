import { Component, ViewChild, ElementRef, OnInit } from '@angular/core';
import { FormService } from './../form.service';
import { FormsModule } from '@angular/forms';
import {
	FontAwesomeModule,
	FaIconLibrary,
} from '@fortawesome/angular-fontawesome';
import { faHouseUser, faTrash } from '@fortawesome/free-solid-svg-icons';

import {
	faPenToSquare,
	faCircleCheck,
	faCircleXmark,
} from '@fortawesome/free-regular-svg-icons';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { CommonModule } from '@angular/common';
import { HeaderComponent } from '../header/header.component';
import { Router} from '@angular/router';
import { LoaderComponent } from '../loader/loader.component';

@Component({
	selector: 'app-profile',
	standalone: true,
	imports: [FontAwesomeModule, CommonModule, FormsModule, HeaderComponent, MatSnackBarModule, LoaderComponent],
	templateUrl: './profile.component.html',
	styleUrl: './profile.component.css',
})
export class ProfileComponent implements OnInit {
	@ViewChild('myName') inputName!: ElementRef;
	@ViewChild('myEmail') inputEmail!: ElementRef;
	isLoading = false;
	user = {
		name: '',
		email: '',
	};

	editedName: string = this.user.name;
	editedEmail: string = this.user.email;

	isEditingName = false;
	isEditingEmail = false;

	constructor(
		library: FaIconLibrary,
		private router: Router,
		private formService: FormService,
		private snackBar: MatSnackBar,
	) {
		library.addIcons(
			faPenToSquare,
			faCircleCheck,
			faCircleXmark,
			faHouseUser,
			faTrash
		);
	}

	ngOnInit(): void {
		this.formService.user_info().subscribe({
			next: (response) => {
				const user_info = JSON.parse(response);
				this.user.name = user_info["name"];
				this.user.email = user_info["email"];
			},
			error: (error) => {
				this.snackBar.open(JSON.parse(error['error'])['message'], 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});
			}
		})
	}

	// Method to enable editing for a specific field
	editField(field: string): void {
		if (field === 'name') {
			this.isEditingName = true;
			this.inputName.nativeElement.focus();
		} else if (field === 'email') {
			this.isEditingEmail = true;
			this.inputEmail.nativeElement.focus();
		}
	}

	// Save changes and disable editing for the specific field
	saveChanges(field: string): void {
		this.isLoading = true;
		if (field === 'name') {
			if (this.editedName !== this.user.name && this.editedName !== "") {
				this.formService.update_name(this.editedName).subscribe({
					next: (response) => {
						this.snackBar.open(JSON.parse(response)['message'], 'Close', {
							duration: 5000, // Snackbar will remain open for 5 seconds
							horizontalPosition: 'center',
							verticalPosition: 'top',
						});
						this.user.name = this.editedName;
						this.isLoading = false;
					},
					error: (error) => {
						this.snackBar.open(JSON.parse(error['error'])['message'], 'Close', {
							duration: 5000, // Snackbar will remain open for 5 seconds
							horizontalPosition: 'center',
							verticalPosition: 'top',
						});
						this.isLoading = false;
					}
				})
			} else {
				this.isLoading = false;
			}
			this.isEditingName = false;

		} else if (field === 'email') {
			if (this.editedEmail !== this.user.email && this.editedEmail !== "") {
				this.formService.update_email(this.editedEmail).subscribe({
					next: (response) => {
						this.snackBar.open(JSON.parse(response)['message'], 'Close', {
							duration: 5000, // Snackbar will remain open for 5 seconds
							horizontalPosition: 'center',
							verticalPosition: 'top',
						});
						this.user.email = this.editedEmail;
						sessionStorage.setItem("new_email", this.editedEmail);
						this.router.navigate(['/otp-page', 'profile-email']);
						this.isLoading = false;
					},
					error: (error) => {
						this.snackBar.open(JSON.parse(error['error'])['message'], 'Close', {
							duration: 5000, // Snackbar will remain open for 5 seconds
							horizontalPosition: 'center',
							verticalPosition: 'top',
						});
						this.isLoading = false;
					}
				})
			} else {
				this.isLoading = false;
			}
			this.isEditingEmail = false;
		}
		return;
	}

	// Cancel editing and revert changes
	cancelChanges(field: string): void {
		if (field === 'name') {
			this.editedName = this.user.name;
			this.isEditingName = false;
		} else if (field === 'email') {
			this.editedEmail = this.user.email;
			this.isEditingEmail = false;
		}
	}

	navigateToHome() {
		this.isLoading = true;
		this.router.navigate(['/home']);
		this.isLoading = false;
	}

	deleteUser() {
		this.isLoading = true;
		this.formService.delete_user(null).subscribe({
			next: (response) => {
				this.snackBar.open(JSON.parse(response)["message"], 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'top',
				});
				this.router.navigate(['/sign-in']);
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
		});
	}

	updatePassword() {
		this.isLoading = true;
		this.router.navigate(['/update-password']);
		this.isLoading = false;
	}
}
