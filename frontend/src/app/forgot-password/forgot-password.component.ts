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
import { LoaderComponent } from '../loader/loader.component';

@Component({
	selector: 'app-forgot-password',
	standalone: true,
	imports: [ReactiveFormsModule, CommonModule, RouterModule, LoaderComponent],
	templateUrl: './forgot-password.component.html',
	styleUrl: './forgot-password.component.css'
})
export class ForgotPasswordComponent {
	isLoading = false;
	forgotPasswordForm!: FormGroup;
	errorMessage: string | null = null;

	constructor(
		private fb: FormBuilder,
		private formService: FormService,
		private router: Router,
	) { }

	ngOnInit(): void {
		this.forgotPasswordForm = this.fb.group({
			email: new FormControl('', [Validators.required, Validators.email]),
		});
	}

	get email() {
		return this.forgotPasswordForm.get('email');
	}

	onSubmit(): void {
		this.isLoading = true;
		if (this.forgotPasswordForm.valid) {
			this.formService.forgot_password(this.forgotPasswordForm.value).subscribe({
				next: (response) => {
					console.log(`${response}.`);
					this.router.navigate(['/otp-page', 'set-password']);
					this.isLoading = false;
				},
				error: (error) => {
					this.errorMessage = JSON.parse(error['error'])['message'];
					this.isLoading = false;
				},
				complete: () => {
					console.log('Login Form Handling Completed.');
				},
			});
			console.log('Form Submitted!', this.forgotPasswordForm.value);
		} else {
			console.log('Form is invalid');
		}
	}
}
