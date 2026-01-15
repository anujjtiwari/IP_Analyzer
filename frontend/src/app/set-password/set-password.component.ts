import { FormService } from './../form.service';
import { Component } from '@angular/core';
import {
	ReactiveFormsModule,
	FormGroup,
	FormControl,
	Validators,
	FormBuilder,
} from '@angular/forms';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import { FaIconLibrary } from '@fortawesome/angular-fontawesome';
import {
	faEye as fasEye,
	faEyeSlash as fasEyeSlash,
} from '@fortawesome/free-solid-svg-icons';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { LoaderComponent } from '../loader/loader.component';

@Component({
	selector: 'app-set-password',
	standalone: true,
	imports: [ReactiveFormsModule, CommonModule, RouterModule, FontAwesomeModule, MatSnackBarModule, LoaderComponent],
	templateUrl: './set-password.component.html',
	styleUrl: './set-password.component.css'
})
export class SetPasswordComponent {
	setPasswordForm!: FormGroup;
	isPasswordVisible = false;
	errorMessage: string | null = null;
	isLoading = false;

	constructor(
		private fb: FormBuilder,
		private formService: FormService,
		private router: Router,
		private snackBar: MatSnackBar,
		library: FaIconLibrary,
	) {
		library.addIcons(fasEye, fasEyeSlash);
	 }

	ngOnInit(): void {
		this.setPasswordForm = this.fb.group({
			password: new FormControl('', [Validators.required]),
		});
	}

	get password() {
		return this.setPasswordForm.get('password');
	}

	onSubmit(): void {
		this.isLoading = true;
		if (this.setPasswordForm.valid) {
			this.formService.set_password(this.setPasswordForm.value).subscribe({
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
					console.log(`Error: ${JSON.parse(error['error'])['message']}.`);
					this.isLoading = false;
				},
				complete: () => {
					console.log("Set Password Form Handling Complete.")
				}
			});
			console.log('Form Submitted!', this.setPasswordForm.value);
		} else {
			console.log('Form is invalid');
			this.isLoading = false;
		}
	}

	togglePasswordVisibility() {
		this.isPasswordVisible = !this.isPasswordVisible;
	}
}
