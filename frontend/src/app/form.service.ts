import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface UserData {
	email: string;
	password: string;
}

export interface FormData {
	ip_domain: string,
	geoLocation: boolean,
	blackList: boolean,
	portScan: boolean,
	reports: boolean
}

interface FormEmail {
	email:string;
}

interface FormPassword {
	password:string;
}

interface UpdatePasswordForm {
	oldPassword:string;
	newPassword:string;
}

@Injectable({
	providedIn: 'root'
})
export class FormService {
	private apiUrl = '/api';
	private json_header = new HttpHeaders({
		'Content-Type': 'application/json'
	});
	constructor(private http: HttpClient) { }

	user_sign_in(userdata: UserData): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/user_sign_in/`, userdata, {
			headers: this.json_header,
			withCredentials: true
		});
	}

	user_sign_up(userdata: UserData): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/user_sign_up/`, userdata, {
			headers: this.json_header,
			withCredentials: true
		});
	}

	user_sign_out(): Observable<string> {
		return this.http.get<string>(`${this.apiUrl}/user_sign_out/`, {
			headers: this.json_header,
			withCredentials: true
		})
	}

	otp_verify(otp: string): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/otp_verify/`, { 'otp': otp }, {
			headers: this.json_header,
			withCredentials: true
		});
	}

	resend_otp(): Observable<string> {
		return this.http.get<string>(`${this.apiUrl}/resend_otp/`, {
			headers: this.json_header,
			withCredentials: true
		})
	}

	get_user_name(): Observable<string> {
		return this.http.get<string>(`${this.apiUrl}/user_name/`, {
			headers: this.json_header,
			withCredentials: true
		})
	}

	compute_results(formData: FormData): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/compute_results/`, formData, {
			headers: this.json_header,
			withCredentials: true
		})
	}

	get_user_list(): Observable<string> {
		return this.http.get<string>(`${this.apiUrl}/user_list/`, {
			headers: this.json_header,
			withCredentials: true
		})
	}

	get_admin_name(): Observable<string> {
		return this.http.get<string>(`${this.apiUrl}/admin_name/`, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	delete_user(user_id:string|null): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/delete_user/`, {"user_id": user_id}, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	lock_user(user_id:string): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/lock_user/`, {"user_id": user_id}, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	unlock_user(user_id:string): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/unlock_user/`, {"user_id": user_id}, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	make_admin(user_id:string): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/make_admin/`, {"user_id": user_id}, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	revoke_admin(user_id:string): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/revoke_admin/`, {"user_id": user_id}, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	forgot_password(formEmail:FormEmail): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/forgot_password/`, formEmail, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	set_password(formPassword:FormPassword): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/set_password/`, formPassword, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	check_set_password_token(): Observable<string> {
		return this.http.get<string>(`${this.apiUrl}/check_set_password_token/`, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	check_sign_in_token(): Observable<string> {
		return this.http.get<string>(`${this.apiUrl}/check_sign_in_token/`, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	is_admin(): Observable<string> {
		return this.http.get<string>(`${this.apiUrl}/is_admin/`, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	user_info(): Observable<string> {
		return this.http.get<string>(`${this.apiUrl}/user_info/`, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	update_name(name:string): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/update_name/`, {"name": name}, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	update_email(email:string): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/update_email/`, {"email":email}, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	set_email(email:string|null): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/set_email/`, {"email":email}, {
			headers:this.json_header,
			withCredentials:true
		})
	}

	update_password(passwordData:UpdatePasswordForm): Observable<string> {
		return this.http.post<string>(`${this.apiUrl}/update_password/`, passwordData, {
			headers:this.json_header,
			withCredentials:true
		})
	}
}
