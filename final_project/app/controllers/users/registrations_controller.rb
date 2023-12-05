class Users::RegistrationsController < Devise::RegistrationsController
    respond_to :json
  def create
    build_resource(sign_up_params)

    if resource.save
      # Generar y asignar el token JWT después de que el usuario se registra
      token = generate_jwt_token(resource)

      sign_in(resource_name, resource)
      render json: { user: resource, token: token }
    else
      clean_up_passwords resource
      set_minimum_password_length
      render json: { errors: resource.errors.full_messages }, status: :unprocessable_entity
    end
  end

  private

  def sign_up_params
    params.require(:user).permit(:email, :password, :password_confirmation)
  end

  def generate_jwt_token(user)
    payload = { user_id: user.id, email: user.email }
    secret = Rails.application.secrets.jwt_secret

    # Verificar que el secreto no sea nulo o vacío antes de codificar el token
    if secret.present?
      JWT.encode(payload, secret, 'HS256')
    else
      raise 'Error: Se debe proporcionar un secreto para generar el token JWT.'
    end
  end
end
