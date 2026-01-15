import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import {
	Component,
	ElementRef,
	ViewChildren,
	QueryList,
} from '@angular/core';
import {
	ReactiveFormsModule,
	FormGroup,
	FormBuilder,
} from '@angular/forms';
import { CommonModule } from '@angular/common';
import { FormService } from '../form.service';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../auth.service';
import { LoaderComponent } from '../loader/loader.component';

@Component({
	selector: 'app-otp-page',
	standalone: true,
	imports: [CommonModule, MatSnackBarModule, ReactiveFormsModule, LoaderComponent],
	templateUrl: './otp-page.component.html',
	styleUrls: ['./otp-page.component.css'],
})
export class OtpPageComponent {
	otp: string[] = new Array(6).fill(''); // Array to store each digit of the OTP
	@ViewChildren('otp1, otp2, otp3, otp4, otp5, otp6')
	otpInputs!: QueryList<ElementRef>;
	targetComponent!: string | null;
	otpForm!: FormGroup;
	errorMessage = "";
	isLoading = false;

	constructor(
		private snackBar: MatSnackBar,
		private formService: FormService,
		private route: ActivatedRoute,
		private router: Router,
		private fb: FormBuilder,
		private authService: AuthService
	) { }

	ngOnInit(): void {
		this.otpForm = this.fb.group({});

		// Retrieve the target component name from path parameters
		this.route.paramMap.subscribe(params => {
			this.targetComponent = params.get('target');
		});

		this.snackBar.open('OTP sent!', 'Close', {
			duration: 5000, // Snackbar will remain open for 5 seconds
			horizontalPosition: 'center',
			verticalPosition: 'bottom'
		});
	}

	moveToNext(event: Event, index: number): void {
		const input = event.target as HTMLInputElement;
		const value = input.value;

		if (value.match(/^[0-9]$/)) {
			this.otp[index] = value;

			if (index < this.otpInputs.length - 1) {
				// Move to the next input
				this.otpInputs.toArray()[index + 1].nativeElement.focus();
			}
		} else {
			// If not a digit, clear the input
			input.value = '';
		}
	}

	handleBackspace(event: KeyboardEvent, index: number): void {
		const input = event.target as HTMLInputElement;

		if (event.key === 'Backspace') {
			if (input.value === '') {
				// If the current input is empty, move to the previous input
				if (index > 0) {
					this.otpInputs.toArray()[index - 1].nativeElement.focus();
				}
			} else {
				// Clear the current input
				this.otp[index] = '';
			}
		}
	}

	onSubmit(): void {
		this.isLoading = true;
		const otpCode = this.otp.join('');
		console.log('Submitted OTP:', otpCode);

		this.formService.otp_verify(otpCode).subscribe({
			next: (response) => {
				console.log(`${response}.`);
				this.snackBar.open('OTP Verified!', 'Close', {
					duration: 5000, // Snackbar will remain open for 5 seconds
					horizontalPosition: 'center',
					verticalPosition: 'bottom',
				});

				if (this.targetComponent?.toLowerCase() == "home") {
					this.authService.login();
				} else if (this.targetComponent?.toLowerCase() === "set-password") {
					this.authService.allowToSetPassword();
				} else if (this.targetComponent?.toLowerCase() === "profile-email") {
					this.formService.set_email(sessionStorage.getItem('new_email')).subscribe({
						next: (response) => {
							this.snackBar.open(JSON.parse(response)["message"], 'Close', {
								duration: 5000, // Snackbar will remain open for 5 seconds
								horizontalPosition: 'center',
								verticalPosition: 'bottom',
							});
						},
						error: (error) => {
							this.snackBar.open(JSON.parse(error['error'])['message'], 'Close', {
								duration: 5000, // Snackbar will remain open for 5 seconds
								horizontalPosition: 'center',
								verticalPosition: 'bottom',
							});
						}
					})
					this.router.navigate([`/sign-in`]);
				}
				
				this.router.navigate([`/${this.targetComponent?.toLowerCase()}`]);
				this.isLoading = false;
			},
			error: (error) => {
				this.errorMessage = JSON.parse(error['error'])['message'];
				console.log(`Error: ${this.errorMessage}.`);
				this.isLoading = false;
			},
			complete: () => {
				console.log('OTP Form Handling Completed.');
			},
		});
	}

	resendOtp(): void {
		this.isLoading = true;
		this.formService.resend_otp().subscribe({
			next: (response) => {
				console.log(`${response}.`);
				this.isLoading = false;
			},
			error: (error) => {
				this.errorMessage = JSON.parse(error['error'])['message'];
				console.log(`Error: ${this.errorMessage}.`);
				this.isLoading = false;
			},
			complete: () => {
				console.log('OTP Resend Handling Completed.');
			},
		});

		this.snackBar.open('OTP has been resent', 'Close', {
			duration: 5000, // Snackbar will remain open for 5 seconds
			horizontalPosition: 'center',
			verticalPosition: 'bottom',
		});
	}

	handlePaste(event: ClipboardEvent, index: number): void {
		const pasteData = event.clipboardData?.getData('text') || '';
		
		// Ensure the pasted data only contains digits
		const filteredData = pasteData.replace(/\D/g, ''); // Remove non-digit characters
		
		// Paste the data starting from the current index
		if (filteredData.length > 0) {
			let currentIndex = index;
	
			for (let i = 0; i < filteredData.length && currentIndex < this.otpInputs.length; i++, currentIndex++) {
				this.otp[currentIndex] = filteredData[i];
				this.otpInputs.toArray()[currentIndex].nativeElement.value = filteredData[i];
			}
	
			// Focus the next empty input field
			if (currentIndex < this.otpInputs.length) {
				this.otpInputs.toArray()[currentIndex].nativeElement.focus();
			}
		}
		
		// Prevent the default paste behavior
		event.preventDefault();
	}
}
