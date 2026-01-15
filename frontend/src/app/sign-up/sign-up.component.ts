import { Component } from '@angular/core';
import { FormService } from './../form.service';
import {
	ReactiveFormsModule,
	FormGroup,
	FormControl,
	Validators,
	FormBuilder,
} from '@angular/forms';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import { FaIconLibrary } from '@fortawesome/angular-fontawesome';
import {
	faEye as fasEye,
	faEyeSlash as fasEyeSlash,
} from '@fortawesome/free-solid-svg-icons';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';
import { LoaderComponent } from '../loader/loader.component';

@Component({
  selector: 'app-sign-up',
  standalone: true,
  imports: [ReactiveFormsModule, FontAwesomeModule, CommonModule, RouterModule, LoaderComponent],
  templateUrl: './sign-up.component.html',
  styleUrl: './sign-up.component.css',
})
export class SignUpComponent {
	signupForm!: FormGroup;
	isPasswordVisible = false;
	errorMessage = "";
	isLoading = false;
	constructor(
		private fb: FormBuilder,
		library: FaIconLibrary,
		private formService: FormService,
		private router: Router,
	) {
		library.addIcons(fasEye, fasEyeSlash);
	}

	ngOnInit(): void {
		this.signupForm = this.fb.group({
			name: new FormControl('', [Validators.required]),
			email: new FormControl('', [Validators.required, Validators.email]),
			password: new FormControl('', [Validators.required]),
		});
	}

	get name() {
		return this.signupForm.get('name');
	}

	get email() {
		return this.signupForm.get('email');
	}

	get password() {
		return this.signupForm.get('password');
	}

	onSubmit(): void {
		this.isLoading = true;
		if (this.signupForm.valid) {
			this.formService.user_sign_up(this.signupForm.value).subscribe({
				next: (response) => {
					console.log(`Response: ${response}.`);
					this.router.navigate(['/otp-page', 'sign-in']);
					this.isLoading = false;
				},
				error: (error) => {
					this.errorMessage = JSON.parse(error['error'])['message'];
					console.log(`Error: ${this.errorMessage}.`);
					this.isLoading = false;
				},
				complete: () => {
					console.log('Sign Up Form Handling Completed.');
				},
			});
			console.log('Form Submitted!', this.signupForm.value);
		} else {
			console.log('Form is invalid');
			this.isLoading = false;
		}
	}

	togglePasswordVisibility() {
		this.isPasswordVisible = !this.isPasswordVisible;
	}


}
