import { FormService } from './../form.service';
import { Component } from '@angular/core';
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
import { AuthService } from '../auth.service';
import { LoaderComponent } from '../loader/loader.component';

@Component({
	selector: 'app-sign-in',
	standalone: true,
	imports: [ReactiveFormsModule, CommonModule, FontAwesomeModule, RouterModule, LoaderComponent],
	templateUrl: './sign-in.component.html',
	styleUrl: './sign-in.component.css'
})

export class SignInComponent {
	loginForm!: FormGroup;
	isPasswordVisible = false;
	errorMessage: string | null = null;
	isLoading = false;

	constructor(
		private fb: FormBuilder,
		library: FaIconLibrary,
		private formService: FormService,
		private router: Router,
		private authService: AuthService
	) {
		library.addIcons(fasEye, fasEyeSlash);
	}

	ngOnInit(): void {

		this.formService.check_sign_in_token().subscribe({
			next: (response) => {
				this.authService.login();
				this.router.navigate(['/home']);
			}, 
			error: (error) => {
				this.authService.logout();
			}
		})

		this.loginForm = this.fb.group({
			email: new FormControl('', [Validators.required, Validators.email]),
			password: new FormControl('', [Validators.required]),
		});
	}

	get email() {
		return this.loginForm.get('email');
	}

	get password() {
		return this.loginForm.get('password');
	}

	onSubmit(): void {
		this.isLoading = true;
		if (this.loginForm.valid) {
			this.formService.user_sign_in(this.loginForm.value).subscribe({
				next: (response) => {
					console.log(`${response}.`);
					this.router.navigate(['/otp-page', 'home']);
					this.isLoading = false;
				},
				error: (error) => {
					console.log(`Error: ${JSON.parse(error['error'])['message']}.`);
					this.errorMessage = 'Invalid email or password';
					this.isLoading = false;
				},
				complete: () => {
					console.log('Login Form Handling Completed.');
				},
			});
			console.log('Form Submitted!', this.loginForm.value);
		} else {
			this.isLoading = false;
			console.log('Form is invalid');
		}
	}

	togglePasswordVisibility() {
		this.isPasswordVisible = !this.isPasswordVisible;
	}
}
